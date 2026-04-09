// @ts-check
/// <reference path="../types/plugin.d.ts" />
/// <reference path="./types.d.ts" />

/**
 * This example keeps the plugin on the lightweight path:
 * it does not request body permissions and only uses headers,
 * action overrides, and response header patches.
 *
 * @param {LoadContext<ExampleConfig>} context
 * @returns {LoadOutput<ExampleState>}
 */
export function on_event(context) {
  const config = context.input.plugin.config || {};
  const originHosts = Array.isArray(config.origin_hosts)
    ? [...new Set(config.origin_hosts.filter(Boolean).map((host) => String(host).toLowerCase()))]
    : [];

  return {
    state: {
      origin_hosts: originHosts,
      mirror_url: config.mirror_url || "https://mirror.example.com/",
      control_header: (config.control_header || "x-anymirror-example").toLowerCase(),
      response_header: (config.response_header || "x-anymirror-example").toLowerCase()
    }
  };
}
