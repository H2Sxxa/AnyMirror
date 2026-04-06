type PluginStage = "on_load" | "on_compile" | "on_request" | "on_response";

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

interface PluginLoadInput {
  plugin: PluginIdentity & {
    config: unknown;
  };
}

interface PluginCompileInput {
  plugin: PluginIdentity & {
    config: unknown;
    state: unknown;
  };
}

interface PluginStagePluginInput extends PluginIdentity {
  config: unknown;
  state: unknown;
  program: unknown;
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
  [key: string]: unknown;
}

interface MatchContext {
  index: number;
  action: PluginAction;
}

interface RequestStageInput {
  plugin: PluginStagePluginInput;
  request: PluginRequestInput;
  matched?: MatchContext;
}

interface ResponseStageInput {
  plugin: PluginStagePluginInput;
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

type LoadContext = PluginContext<PluginLoadInput>;
type CompileContext = PluginContext<PluginCompileInput>;
type RequestContext = PluginContext<RequestStageInput>;
type ResponseContext = PluginContext<ResponseStageInput>;

interface LoadOutput {
  state?: unknown;
}

interface CompileOutput {
  program?: PluginCompiledProgram;
}

interface RequestOutput {
  action?: PluginAction;
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string | null>;
    body?: {
      text?: string;
      json?: unknown;
      base64?: string;
    };
  };
}

interface ResponseOutput {
  status?: number;
  headers?: Record<string, string | null>;
  body?: {
    text?: string;
    json?: unknown;
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
