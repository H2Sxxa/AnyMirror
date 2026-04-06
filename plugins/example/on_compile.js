// @ts-check
/// <reference path="../types/plugin.d.ts" />

/**
 * @param {CompileContext} context
 * @returns {CompileOutput}
 */
export function on_event(context) {
  const state =
    /** @type {{ host?: string, mirror_url?: string, control_header?: string, response_header?: string }} */ (
      context.input.plugin.state || {}
    );

  return {
    program: {
      control_header: state.control_header || "x-anymirror-example",
      response_header: state.response_header || "x-anymirror-example",
      rules: [
        {
          match: {
            host: state.host || "httpbin.org"
          },
          action: {
            type: "mirror",
            upstream: {
              url: state.mirror_url || "https://httpbin.org/anything/mirror"
            }
          }
        }
      ]
    }
  };
}
