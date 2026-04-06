// @ts-check
/// <reference path="../types/plugin.d.ts" />
/// <reference path="./types.d.ts" />

/**
 * @param {CompileContext<ExampleConfig, ExampleState>} context
 * @returns {CompileOutput<ExampleProgram>}
 */
export function on_event(context) {
  const state = context.input.plugin.state || {
    host: "example.com",
    mirror_url: "https://mirror.example.com/",
    control_header: "x-anymirror-example",
    response_header: "x-anymirror-example"
  };

  return {
    program: {
      control_header: state.control_header || "x-anymirror-example",
      response_header: state.response_header || "x-anymirror-example",
      rules: [
        {
          match: {
            host: state.host || "example.com"
          },
          action: {
            type: "mirror",
            upstream: {
              url: state.mirror_url || "https://mirror.example.com/"
            }
          }
        }
      ]
    }
  };
}
