// @ts-check
/// <reference path="../types/plugin.d.ts" />

import console from "@anymirror/console";

/**
 * @param {RequestContext} context
 * @returns {RequestOutput | null}
 */
export function on_event(context) {
  const program =
    /** @type {{ control_header?: string }} */ (context.input.plugin.program || {});
  const controlHeader = (program.control_header || "x-anymirror-example").toLowerCase();
  const controlValue =
    context.input.request.headers.find(
      (header) => header.name.toLowerCase() === controlHeader
    )?.value.toLowerCase() || "mirror";

  if (!context.input.matched) {
    return null;
  }

  console.info(`example plugin control=${controlValue} url=${context.input.request.url}`);

  if (controlValue === "direct") {
    return {
      action: {
        type: "direct"
      }
    };
  }

  if (controlValue === "reject") {
    return {
      action: {
        type: "reject",
        status: 451,
        message: "rejected by example plugin"
      }
    };
  }

  return null;
}
