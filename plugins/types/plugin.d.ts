type PluginStage = "on_load" | "on_compile" | "on_request" | "on_response";

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

interface PluginStagePermissions {
  body: boolean;
}

interface PluginPermissions {
  on_request: PluginStagePermissions;
  on_response: PluginStagePermissions;
}

interface PluginIdentity {
  name: string;
  engine: string;
  permissions: PluginPermissions;
}

interface HeaderInput {
  name: string;
  value: string;
}

interface BodyInput {
  kind: "text" | "base64";
  value: string;
}

interface PluginLoadInput<TConfig = JsonValue> {
  plugin: PluginIdentity & {
    config: TConfig;
  };
}

interface PluginCompileInput<TConfig = JsonValue, TState = JsonValue> {
  plugin: PluginIdentity & {
    config: TConfig;
    state: TState;
  };
}

interface PluginStagePluginInput<
  TConfig = JsonValue,
  TState = JsonValue,
  TProgram = PluginCompiledProgram
> extends PluginIdentity {
  config: TConfig;
  state: TState;
  program: TProgram;
}

interface PluginRequestInput {
  source: string;
  method: string;
  url: string;
  scheme: string;
  host?: string;
  port?: number;
  path: string;
  query?: string;
  headers: HeaderInput[];
  body?: BodyInput;
}

interface PluginMirrorUpstream {
  url: string;
  sni?: string;
  host?: string;
  connect_host?: string;
  connect_ip?: string;
  dns?: {
    mode: "system" | "udp" | "dot" | "doh";
    server?: string;
  };
}

interface PluginDirectAction {
  type: "direct";
}

interface PluginMirrorAction {
  type: "mirror";
  upstream: PluginMirrorUpstream;
}

interface PluginRejectAction {
  type: "reject";
  status?: number;
  message?: string;
}

type PluginAction = PluginDirectAction | PluginMirrorAction | PluginRejectAction;

interface PluginRuleMatch {
  exact?: string;
  prefix?: string;
  host?: string;
  hosts?: string[];
  host_suffix?: string;
  scheme?: "http" | "https";
  port?: number;
  path_prefix?: string;
  path_suffix?: string;
}

interface PluginCompiledRule {
  match: PluginRuleMatch;
  action: PluginAction;
}

interface PluginCompiledProgram {
  rules?: PluginCompiledRule[];
  [key: string]: JsonValue | PluginCompiledRule[] | undefined;
}

interface MatchContext {
  index: number;
  action: PluginAction;
}

interface RequestStageInput<
  TConfig = JsonValue,
  TState = JsonValue,
  TProgram = PluginCompiledProgram
> {
  plugin: PluginStagePluginInput<TConfig, TState, TProgram>;
  request: PluginRequestInput;
  matched?: MatchContext;
}

interface ResponseStageInput<
  TConfig = JsonValue,
  TState = JsonValue,
  TProgram = PluginCompiledProgram
> {
  plugin: PluginStagePluginInput<TConfig, TState, TProgram>;
  request: PluginRequestInput;
  matched?: MatchContext;
  resolved_action: PluginAction;
  response: {
    status: number;
    headers: HeaderInput[];
    body?: BodyInput;
  };
}

interface PluginContext<TInput> {
  plugin: string;
  stage: PluginStage;
  input: TInput;
}

type LoadContext<TConfig = JsonValue> = PluginContext<PluginLoadInput<TConfig>>;
type CompileContext<TConfig = JsonValue, TState = JsonValue> = PluginContext<
  PluginCompileInput<TConfig, TState>
>;
type RequestContext<
  TConfig = JsonValue,
  TState = JsonValue,
  TProgram = PluginCompiledProgram
> = PluginContext<RequestStageInput<TConfig, TState, TProgram>>;
type ResponseContext<
  TConfig = JsonValue,
  TState = JsonValue,
  TProgram = PluginCompiledProgram
> = PluginContext<ResponseStageInput<TConfig, TState, TProgram>>;

interface LoadOutput<TState = JsonValue> {
  state?: TState;
}

interface CompileOutput<TProgram = PluginCompiledProgram> {
  program?: TProgram;
}

interface RequestOutput {
  action?: PluginAction;
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string | null>;
    body?: {
      text?: string;
      json?: JsonValue;
      base64?: string;
    };
  };
}

interface ResponseOutput {
  status?: number;
  headers?: Record<string, string | null>;
  body?: {
    text?: string;
    json?: JsonValue;
    base64?: string;
  };
}

declare module "@anymirror/console" {
  interface PluginConsole {
    log(...args: unknown[]): void;
    info(...args: unknown[]): void;
    warn(...args: unknown[]): void;
    error(...args: unknown[]): void;
    debug(...args: unknown[]): void;
  }

  export const log: (...args: unknown[]) => void;
  export const info: (...args: unknown[]) => void;
  export const warn: (...args: unknown[]) => void;
  export const error: (...args: unknown[]) => void;
  export const debug: (...args: unknown[]) => void;
  export const console: PluginConsole;

  export default console;
}
