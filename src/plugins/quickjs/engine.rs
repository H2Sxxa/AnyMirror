use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use rquickjs::{
    Context as QuickJsContext, Function, IntoJs, Module, Null, Object, Persistent,
    Runtime as QuickJsRuntime, Value as QuickJsValue, function::Func,
};
use serde_json::Value;
use tokio::sync::oneshot;
use tracing::Span;

use super::loader::{PluginModuleLoader, PluginModuleResolver, SharedLoaderState};
use crate::plugins::{PluginStage, ScriptRuntimePool};
use crate::workers::Workers;

pub struct QuickJsPool {
    tx: Mutex<Option<mpsc::Sender<QuickJsTask>>>,
    receiver: Arc<Mutex<mpsc::Receiver<QuickJsTask>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    worker_registry: Workers,
    max_workers: usize,
    pending_tasks: Arc<AtomicUsize>,
    next_worker_index: AtomicUsize,
}

struct QuickJsTask {
    plugin_name: String,
    stage: PluginStage,
    source: String,
    plugin_root: PathBuf,
    entry_module_name: String,
    input: Value,
    trace: QuickJsTraceContext,
    reply: oneshot::Sender<Result<Value>>,
}

struct QuickJsTraceContext {
    parent_span: Span,
    enqueued_at: Instant,
}

struct QuickJsWorker {
    handler_cache: Mutex<std::collections::HashMap<String, Persistent<Function<'static>>>>,
    console_state: Arc<Mutex<ConsoleState>>,
    loader_state: SharedLoaderState,
    context: QuickJsContext,
    // Drop runtime last, after persistent handles and context have been released.
    runtime: QuickJsRuntime,
}

#[derive(Default)]
struct ConsoleState {
    plugin_name: String,
    stage: String,
}

impl QuickJsPool {
    pub fn new(worker_count: usize, worker_registry: Workers) -> Result<Self> {
        if worker_count == 0 {
            return Err(anyhow!(
                "QuickJS worker pool max_workers must be greater than zero"
            ));
        }

        let (tx, rx) = mpsc::channel::<QuickJsTask>();
        let shared_rx = Arc::new(Mutex::new(rx));

        Ok(Self {
            tx: Mutex::new(Some(tx)),
            receiver: shared_rx,
            workers: Mutex::new(Vec::with_capacity(worker_count)),
            worker_registry,
            max_workers: worker_count,
            pending_tasks: Arc::new(AtomicUsize::new(0)),
            next_worker_index: AtomicUsize::new(0),
        })
    }

    fn ensure_worker_capacity(&self, pending_tasks: usize) -> Result<()> {
        let mut workers = self
            .workers
            .lock()
            .map_err(|_| anyhow!("QuickJS worker pool worker lock poisoned"))?;
        let active_workers = workers.len();
        let should_spawn = active_workers == 0
            || (pending_tasks > active_workers && active_workers < self.max_workers);
        if !should_spawn {
            return Ok(());
        }

        let worker_index = self.next_worker_index.fetch_add(1, Ordering::Relaxed);
        let worker_rx = self.receiver.clone();
        let pending_tasks = self.pending_tasks.clone();
        let worker_registry = self.worker_registry.clone();
        let worker_name = format!("plugin-quickjs-worker-{worker_index}");
        let builder = thread::Builder::new().name(format!("plugin-quickjs-worker-{worker_index}"));
        let handle = builder
            .spawn(move || {
                let _tracked_worker = worker_registry.track_external_thread(worker_name);
                quickjs_worker_loop(worker_rx, pending_tasks)
            })
            .context("failed to spawn QuickJS plugin worker thread")?;
        workers.push(handle);
        Ok(())
    }
}

#[async_trait]
impl ScriptRuntimePool for QuickJsPool {
    async fn execute(
        &self,
        plugin_name: &str,
        stage: PluginStage,
        plugin_root: &Path,
        entry_module_name: &str,
        source: &str,
        input: &Value,
    ) -> Result<Value> {
        let pending_tasks = self.pending_tasks.fetch_add(1, Ordering::AcqRel) + 1;
        if let Err(error) = self.ensure_worker_capacity(pending_tasks) {
            self.pending_tasks.fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }

        let tx = {
            let guard = self
                .tx
                .lock()
                .map_err(|_| anyhow!("QuickJS worker pool sender lock poisoned"))?;
            guard
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("QuickJS worker pool is shut down"))?
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(QuickJsTask {
            plugin_name: plugin_name.to_string(),
            stage,
            source: source.to_string(),
            plugin_root: plugin_root.to_path_buf(),
            entry_module_name: entry_module_name.to_string(),
            input: input.clone(),
            trace: QuickJsTraceContext::capture_current(),
            reply: reply_tx,
        })
        .map_err(|_| {
            self.pending_tasks.fetch_sub(1, Ordering::AcqRel);
            anyhow!("failed to submit task to QuickJS worker pool")
        })?;

        reply_rx
            .await
            .map_err(|_| anyhow!("QuickJS worker dropped plugin task result"))?
    }
}

impl Drop for QuickJsPool {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.tx.lock() {
            guard.take();
        }

        if let Ok(mut workers) = self.workers.lock() {
            for worker in workers.drain(..) {
                let _ = worker.join();
            }
        }
    }
}

impl QuickJsWorker {
    fn new() -> Result<Self> {
        let loader_state = SharedLoaderState::new();
        let console_state = Arc::new(Mutex::new(ConsoleState::default()));
        let runtime = QuickJsRuntime::new().context("failed to create QuickJS runtime")?;
        runtime.set_loader(
            PluginModuleResolver::new(loader_state.clone()),
            PluginModuleLoader::new(loader_state.clone()),
        );
        let context = QuickJsContext::full(&runtime).context("failed to create QuickJS context")?;
        context.with(|ctx| install_console_bridge(&ctx, console_state.clone()))?;

        Ok(Self {
            handler_cache: Mutex::new(std::collections::HashMap::new()),
            console_state,
            loader_state,
            context,
            runtime,
        })
    }

    fn execute(&self, task: &QuickJsTask) -> Result<Value> {
        let _runtime = &self.runtime;
        self.loader_state.prepare_entry_module(
            &task.plugin_root,
            &task.entry_module_name,
            &task.source,
        )?;
        {
            let mut console_state = self
                .console_state
                .lock()
                .map_err(|_| anyhow!("QuickJS console state lock poisoned"))?;
            console_state.plugin_name = task.plugin_name.clone();
            console_state.stage = task.stage.label().to_string();
        }

        self.context
            .with(|ctx| self.execute_quickjs_task(ctx, task))
    }

    fn execute_quickjs_task(&self, ctx: rquickjs::Ctx<'_>, task: &QuickJsTask) -> Result<Value> {
        let handler = self.load_stage_handler(&ctx, task)?;
        let context_value = build_js_context_value(&ctx, task)?;
        let result: QuickJsValue<'_> = handler.call((context_value,)).with_context(|| {
            format!(
                "failed to execute QuickJS stage handler for plugin `{}` at stage `{}`",
                task.plugin_name,
                task.stage.label()
            )
        })?;
        let encoded = encode_result_json(&ctx, &task.plugin_name, task.stage, result)?;
        serde_json::from_str(&encoded).with_context(|| {
            format!(
                "QuickJS returned invalid JSON for plugin `{}` at stage `{}`",
                task.plugin_name,
                task.stage.label()
            )
        })
    }

    fn load_stage_handler<'js>(
        &self,
        ctx: &rquickjs::Ctx<'js>,
        task: &QuickJsTask,
    ) -> Result<Function<'js>> {
        if let Some(handler) = self
            .handler_cache
            .lock()
            .map_err(|_| anyhow!("QuickJS handler cache lock poisoned"))?
            .get(&task.entry_module_name)
            .cloned()
        {
            return handler.restore(ctx).with_context(|| {
                format!(
                    "failed to restore cached QuickJS stage handler for plugin `{}` at stage `{}`",
                    task.plugin_name,
                    task.stage.label()
                )
            });
        }

        let namespace: Object<'js> = Module::import(ctx, task.entry_module_name.as_str())
            .with_context(|| {
                format!(
                    "failed to import QuickJS stage module for plugin `{}` at stage `{}`",
                    task.plugin_name,
                    task.stage.label()
                )
            })?
            .finish()
            .with_context(|| {
                format!(
                    "QuickJS stage module promise failed for plugin `{}` at stage `{}`",
                    task.plugin_name,
                    task.stage.label()
                )
            })?;
        let handler: Function<'js> = namespace.get("default").with_context(|| {
            format!(
                "failed to read QuickJS stage handler for plugin `{}` at stage `{}`",
                task.plugin_name,
                task.stage.label()
            )
        })?;
        let persistent = Persistent::save(ctx, handler.clone());
        self.handler_cache
            .lock()
            .map_err(|_| anyhow!("QuickJS handler cache lock poisoned"))?
            .insert(task.entry_module_name.clone(), persistent);
        Ok(handler)
    }
}

fn quickjs_worker_loop(
    receiver: Arc<Mutex<mpsc::Receiver<QuickJsTask>>>,
    pending_tasks: Arc<AtomicUsize>,
) {
    let worker = match QuickJsWorker::new() {
        Ok(worker) => worker,
        Err(error) => {
            tracing::error!(error = %error, "Failed to initialize QuickJS worker");
            return;
        }
    };

    loop {
        let task = {
            let lock = match receiver.lock() {
                Ok(lock) => lock,
                Err(_) => return,
            };
            match lock.recv() {
                Ok(task) => task,
                Err(_) => return,
            }
        };

        let execute_span = build_quickjs_execute_span(&task);
        let result = {
            let _entered = execute_span.enter();
            worker.execute(&task)
        };
        pending_tasks.fetch_sub(1, Ordering::AcqRel);
        let _ = task.reply.send(result);
    }
}

impl QuickJsTraceContext {
    fn capture_current() -> Self {
        Self {
            parent_span: Span::current(),
            enqueued_at: Instant::now(),
        }
    }
}

fn build_quickjs_execute_span(task: &QuickJsTask) -> Span {
    tracing::info_span!(
        parent: &task.trace.parent_span,
        "plugin.quickjs.execute",
        plugin = %task.plugin_name,
        stage = task.stage.label(),
        queue_wait_ms = elapsed_millis(task.trace.enqueued_at)
    )
}

fn elapsed_millis(start: Instant) -> u64 {
    match u64::try_from(start.elapsed().as_millis()) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn install_console_bridge(
    ctx: &rquickjs::Ctx<'_>,
    console_state: Arc<Mutex<ConsoleState>>,
) -> Result<()> {
    let emit = make_console_bridge(console_state);
    ctx.globals()
        .set("__anymirror_console_emit", Func::from(emit))
        .context("failed to attach console bridge to QuickJS globals")?;

    Ok(())
}

fn make_console_bridge(
    console_state: Arc<Mutex<ConsoleState>>,
) -> impl Fn(String, String) + Send + Sync + 'static {
    move |level: String, message: String| {
        let state = match console_state.lock() {
            Ok(state) => state,
            Err(_) => {
                tracing::error!(message = %message, "Plugin console state lock poisoned");
                return;
            }
        };
        match level.as_str() {
            "error" => tracing::error!(
                plugin = %state.plugin_name,
                stage = %state.stage,
                message = %message,
                "Plugin console"
            ),
            "warn" => tracing::warn!(
                plugin = %state.plugin_name,
                stage = %state.stage,
                message = %message,
                "Plugin console"
            ),
            "debug" => tracing::debug!(
                plugin = %state.plugin_name,
                stage = %state.stage,
                message = %message,
                "Plugin console"
            ),
            _ => tracing::info!(
                plugin = %state.plugin_name,
                stage = %state.stage,
                message = %message,
                "Plugin console"
            ),
        }
    }
}

fn encode_result_json<'js>(
    ctx: &rquickjs::Ctx<'js>,
    plugin_name: &str,
    stage: PluginStage,
    result: QuickJsValue<'js>,
) -> Result<String> {
    if result.is_undefined() {
        return Ok("null".to_string());
    }

    let encoded = ctx.json_stringify(result).with_context(|| {
        format!(
            "failed to stringify QuickJS result for plugin `{}` at stage `{}`",
            plugin_name,
            stage.label()
        )
    })?;

    let encoded = encoded.ok_or_else(|| {
        anyhow!(
            "QuickJS stage result for plugin `{}` at stage `{}` is not JSON-serializable",
            plugin_name,
            stage.label()
        )
    })?;

    encoded
        .to_string()
        .context("failed to convert QuickJS string into Rust string")
}

fn build_js_context_value<'js>(
    ctx: &rquickjs::Ctx<'js>,
    task: &QuickJsTask,
) -> Result<Object<'js>> {
    let context = Object::new(ctx.clone()).context("failed to create QuickJS plugin context")?;
    context
        .set("plugin", task.plugin_name.as_str())
        .context("failed to attach plugin name to QuickJS context")?;
    context
        .set("stage", task.stage.label())
        .context("failed to attach plugin stage to QuickJS context")?;
    let input = json_to_js_value(ctx, &task.input)?;
    context
        .set("input", input)
        .context("failed to attach plugin input to QuickJS context")?;
    Ok(context)
}

fn json_to_js_value<'js>(ctx: &rquickjs::Ctx<'js>, value: &Value) -> Result<QuickJsValue<'js>> {
    match value {
        Value::Null => Null
            .into_js(ctx)
            .context("failed to convert null into QuickJS value"),
        Value::Bool(boolean) => boolean
            .into_js(ctx)
            .context("failed to convert bool into QuickJS value"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer
                    .into_js(ctx)
                    .context("failed to convert integer into QuickJS value")
            } else if let Some(unsigned) = number.as_u64() {
                unsigned
                    .into_js(ctx)
                    .context("failed to convert unsigned integer into QuickJS value")
            } else if let Some(float) = number.as_f64() {
                float
                    .into_js(ctx)
                    .context("failed to convert float into QuickJS value")
            } else {
                Err(anyhow!("unsupported JSON number for QuickJS conversion"))
            }
        }
        Value::String(string) => string
            .as_str()
            .into_js(ctx)
            .context("failed to convert string into QuickJS value"),
        Value::Array(items) => {
            let array = rquickjs::Array::new(ctx.clone())
                .context("failed to create QuickJS array for JSON conversion")?;
            for (index, item) in items.iter().enumerate() {
                let item_value = json_to_js_value(ctx, item)?;
                array.set(index, item_value).with_context(|| {
                    format!("failed to set QuickJS array item at index {index}")
                })?;
            }
            array
                .into_js(ctx)
                .context("failed to convert array into QuickJS value")
        }
        Value::Object(map) => {
            let object = Object::new(ctx.clone())
                .context("failed to create QuickJS object for JSON conversion")?;
            for (key, item) in map {
                let item_value = json_to_js_value(ctx, item)?;
                object
                    .set(key.as_str(), item_value)
                    .with_context(|| format!("failed to set QuickJS object property `{key}`"))?;
            }
            object
                .into_js(ctx)
                .context("failed to convert object into QuickJS value")
        }
    }
}

impl PluginStage {
    fn label(self) -> &'static str {
        match self {
            Self::Load => "on_load",
            Self::Compile => "on_compile",
            Self::Request => "on_request",
            Self::Response => "on_response",
        }
    }
}
