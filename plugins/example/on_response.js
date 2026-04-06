// @ts-check
/// <reference path="../types/plugin.d.ts" />

/**
 * @param {ResponseContext} context
 * @returns {ResponseOutput | null}
 */
export function on_event(context) {
  const program =
    /** @type {{ response_header?: string }} */ (context.input.plugin.program || {});
  const responseHeader = (program.response_header || "x-anymirror-example").toLowerCase();

  return {
    headers: {
      [responseHeader]: context.input.plugin.name,
      [`${responseHeader}-action`]: context.input.resolved_action.type,
      [`${responseHeader}-matched`]: context.input.matched ? "true" : "false"
    }
  };
}
