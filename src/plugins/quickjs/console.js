const stringifyValue = (value) => {
  if (typeof value === "string") {
    return value;
  }
  if (value === null) {
    return "null";
  }
  if (value === undefined) {
    return "undefined";
  }
  try {
    return typeof value === "object" ? JSON.stringify(value) : String(value);
  } catch (_) {
    return String(value);
  }
};

const joinArgs = (args) => args.map(stringifyValue).join(" ");

export const log = (...args) => globalThis.__anymirror_console_emit("info", joinArgs(args));
export const info = (...args) => globalThis.__anymirror_console_emit("info", joinArgs(args));
export const warn = (...args) => globalThis.__anymirror_console_emit("warn", joinArgs(args));
export const error = (...args) => globalThis.__anymirror_console_emit("error", joinArgs(args));
export const debug = (...args) => globalThis.__anymirror_console_emit("debug", joinArgs(args));

export const console = Object.freeze({
  log,
  info,
  warn,
  error,
  debug,
});

export default console;
