// @ts-check
/// <reference path="../types/plugin.d.ts" />
/// <reference path="./types.d.ts" />

/**
 * @param {CompileContext<ExampleConfig, ExampleState>} context
 * @returns {CompileOutput<ExampleProgram>}
 */
export function on_event(context) {
  const state = context.input.plugin.state || {
    origin_hosts: [],
    mirror_url: "https://mirror.example.com/",
    control_header: "x-anymirror-example",
    response_header: "x-anymirror-example"
  };
  const originHosts = Array.isArray(state.origin_hosts) ? state.origin_hosts : [];
  /** @type {PluginCompiledRule[]} */
  const rules =
    originHosts.length === 0
      ? []
      : [
          {
            match: {
              hosts: originHosts
            },
            action: /** @type {PluginMirrorAction} */ ({
              type: "mirror",
              upstream: {
                url: state.mirror_url || "https://mirror.example.com/"
              }
            })
          }
        ];

  return {
    program: {
      origin_hosts: originHosts,
      mirror_url: state.mirror_url || "https://mirror.example.com/",
      control_header: state.control_header || "x-anymirror-example",
      response_header: state.response_header || "x-anymirror-example",
      rules
    }
  };
}
