use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use rquickjs::{
    Ctx, Module,
    loader::{Loader, Resolver},
};

const CONSOLE_MODULE_SPECIFIER: &str = "@anymirror/console";
const CONSOLE_MODULE_SOURCE: &str = include_str!("console.js");

#[derive(Clone)]
pub(crate) struct SharedLoaderState {
    inner: Arc<Mutex<LoaderState>>,
}

struct LoaderState {
    current_plugin_root: PathBuf,
    entry_modules: std::collections::HashMap<String, String>,
}

impl SharedLoaderState {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LoaderState {
                current_plugin_root: PathBuf::new(),
                entry_modules: std::collections::HashMap::new(),
            })),
        }
    }

    pub(crate) fn prepare_entry_module(
        &self,
        plugin_root: &Path,
        entry_module_name: &str,
        entry_source: &str,
    ) -> Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| anyhow!("plugin module loader state lock poisoned"))?;
        state.current_plugin_root = plugin_root.to_path_buf();
        state.entry_modules.insert(
            entry_module_name.to_string(),
            build_entry_module_source(entry_source),
        );
        Ok(())
    }

    fn current_plugin_root(&self) -> Result<PathBuf> {
        let state = self
            .inner
            .lock()
            .map_err(|_| anyhow!("plugin module loader state lock poisoned"))?;
        Ok(state.current_plugin_root.clone())
    }

    fn entry_module_source(&self, module_name: &str) -> Result<Option<String>> {
        let state = self
            .inner
            .lock()
            .map_err(|_| anyhow!("plugin module loader state lock poisoned"))?;
        Ok(state.entry_modules.get(module_name).cloned())
    }
}

pub(crate) struct PluginModuleResolver {
    state: SharedLoaderState,
}

impl PluginModuleResolver {
    pub(crate) fn new(state: SharedLoaderState) -> Self {
        Self { state }
    }
}

impl Resolver for PluginModuleResolver {
    fn resolve<'js>(
        &mut self,
        _ctx: &Ctx<'js>,
        base: &str,
        name: &str,
    ) -> rquickjs::Result<String> {
        if name == CONSOLE_MODULE_SPECIFIER {
            return Ok(CONSOLE_MODULE_SPECIFIER.to_string());
        }

        let plugin_root = self.state.current_plugin_root().map_err(|error| {
            rquickjs::Error::new_resolving_message(base, name, error.to_string())
        })?;
        let module_path =
            resolve_plugin_module_file(&plugin_root, base, name).map_err(|error| {
                rquickjs::Error::new_resolving_message(base, name, error.to_string())
            })?;

        normalize_module_name(&module_path)
            .map_err(|error| rquickjs::Error::new_resolving_message(base, name, error.to_string()))
    }
}

pub(crate) struct PluginModuleLoader {
    state: SharedLoaderState,
}

impl PluginModuleLoader {
    pub(crate) fn new(state: SharedLoaderState) -> Self {
        Self { state }
    }
}

impl Loader for PluginModuleLoader {
    fn load<'js>(&mut self, ctx: &Ctx<'js>, name: &str) -> rquickjs::Result<Module<'js>> {
        if name == CONSOLE_MODULE_SPECIFIER {
            return Module::declare(ctx.clone(), name, CONSOLE_MODULE_SOURCE);
        }

        if let Some(source) = self
            .state
            .entry_module_source(name)
            .map_err(|error| rquickjs::Error::new_loading_message(name, error.to_string()))?
        {
            return Module::declare(ctx.clone(), name, source);
        }

        let source = std::fs::read(name)
            .map_err(|error| rquickjs::Error::new_loading_message(name, error.to_string()))?;
        Module::declare(ctx.clone(), name, source)
    }
}

fn build_entry_module_source(source: &str) -> String {
    format!(
        r#"
{source}

const __anymirror_stage_handler =
  typeof on_event === "function" ? on_event :
  null;

export default __anymirror_stage_handler;
"#
    )
}

fn normalize_module_name(path: &Path) -> Result<String> {
    let canonical = path.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize plugin module path `{}`",
            path.display()
        )
    })?;
    Ok(canonical.to_string_lossy().replace('\\', "/"))
}

fn resolve_plugin_module_file(plugin_root: &Path, base: &str, name: &str) -> Result<PathBuf> {
    if name == CONSOLE_MODULE_SPECIFIER {
        bail!("console module is builtin and should not resolve to a file");
    }

    let candidate = if name.starts_with('.') {
        let base_path = PathBuf::from(base);
        let base_dir = base_path.parent().ok_or_else(|| {
            anyhow!("plugin module `{base}` does not have a parent directory for relative imports")
        })?;
        base_dir.join(name)
    } else {
        plugin_root.join(name)
    };

    let with_extension = if candidate.extension().is_some() {
        candidate
    } else {
        candidate.with_extension("js")
    };

    Ok(with_extension)
}
