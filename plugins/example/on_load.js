// @ts-check
/// <reference path="../types/plugin.d.ts" />

/**
 * This example keeps the plugin on the lightweight path:
 * it does not request body permissions and only uses headers,
 * action overrides, and response header patches.
 *
 * @param {LoadContext} context
 * @returns {LoadOutput}
 */
export function on_event(context) {
  const config =
    /** @type {{ host?: string, mirror_url?: string, control_header?: string, response_header?: string }} */ (
      context.input.plugin.config || {}
    );

  return {
    state: {
      host: config.host || "httpbin.org",
      mirror_url: config.mirror_url || "https://httpbin.org/anything/mirror",
      control_header: (config.control_header || "x-anymirror-example").toLowerCase(),
      response_header: (config.response_header || "x-anymirror-example").toLowerCase()
    }
  };
}
