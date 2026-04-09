// @ts-check
/// <reference path="../types/plugin.d.ts" />
/// <reference path="./types.d.ts" />

import console from "@anymirror/console";

/**
 * @param {string} mirrorBaseUrl
 * @returns {{ scheme: string; authority: string; path: string }}
 */
function parseMirrorBaseUrl(mirrorBaseUrl) {
  const match = /^(https?):\/\/([^/?#]+)(\/[^?#]*)?$/i.exec(mirrorBaseUrl);

  if (!match) {
    throw new Error(`invalid mirror_url: ${mirrorBaseUrl}`);
  }

  return {
    scheme: match[1].toLowerCase(),
    authority: match[2],
    path: match[3] || "/"
  };
}

/**
 * @param {string} mirrorBaseUrl
 * @param {string} requestPath
 * @param {string | undefined} requestQuery
 * @returns {string}
 */
function buildMirrorUrl(mirrorBaseUrl, requestPath, requestQuery) {
  const mirrorBase = parseMirrorBaseUrl(mirrorBaseUrl);
  const basePath = mirrorBase.path === "/" ? "" : mirrorBase.path.replace(/\/+$/, "");
  const normalizedRequestPath = requestPath && requestPath.startsWith("/") ? requestPath : `/${requestPath || ""}`;
  const combinedPath =
    normalizedRequestPath === "/" ? basePath || "/" : `${basePath}${normalizedRequestPath}`;
  const query = requestQuery ? `?${requestQuery}` : "";

  return `${mirrorBase.scheme}://${mirrorBase.authority}${combinedPath}${query}`;
}

/**
 * @param {RequestContext<ExampleConfig, ExampleState, ExampleProgram>} context
 * @returns {RequestOutput | null}
 */
export function on_event(context) {
  const program = context.input.plugin.program;
  const controlHeader = (program.control_header || "x-anymirror-example").toLowerCase();
  const controlValue =
    context.input.request.headers.find(
      (header) => header.name.toLowerCase() === controlHeader
    )?.value.toLowerCase() || "mirror";
  const hasOriginRules = Array.isArray(program.rules) && program.rules.length > 0;

  if (hasOriginRules && !context.input.matched) {
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

  return {
    action: {
      type: "mirror",
      upstream: {
        url: buildMirrorUrl(
          program.mirror_url || "https://mirror.example.com/",
          context.input.request.path,
          context.input.request.query
        )
      }
    }
  };
}
