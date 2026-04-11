# Example Plugin

This example is intentionally small and easy to verify once you replace the placeholder origin and
mirror with hosts that are reachable from your current network environment.

It demonstrates:

- `on_load`: read plugin config
- `on_compile`: compile plugin runtime metadata from config/state
- `on_request`: provide default `mirror` behavior and switch it with a request header
- `on_response`: add visible response headers

It does **not** request body permissions, so it stays on the lightweight plugin path.
It is easiest to validate in **explicit mode** with a plain HTTP request.

## Suggested Config

```yaml
listen: 127.0.0.1:8787

plugins:
  enabled: true
  workers: 4
  includes:
    - name: example
      match:
        hosts:
          - example.com
          - www.example.com
      config:
        origin_hosts:
          - example.com
          - www.example.com
        mirror_url: https://mirror.example.com/
        control_header: x-anymirror-example
        response_header: x-anymirror-example
```

## Behavior

The default behavior is:

- the outer `action: plugin` rule decides which requests invoke the plugin
- `plugins.includes[].match`, when present, auto-registers an implicit `action: plugin` ingress rule
- `origin_hosts`, when configured, becomes a simple internal `hosts` matcher for the example plugin
- `on_request` mirrors to the configured base URL while preserving the original request path and query unless overridden

At request time, `on_request` checks the `x-anymirror-example` header:

- missing or `mirror`: keep the compiled `mirror`
- `direct`: override to `direct`
- `reject`: override to `reject`

At response time, `on_response` adds:

- `x-anymirror-example: example`
- `x-anymirror-example-action: mirror|direct`
- `x-anymirror-example-matched: true|false`

## Quick Verification

Start AnyMirror in explicit mode:

```bash
anymirror --mode explicit --config config.yml
```

Before running the commands below, change the outer plugin rule and `mirror_url` to a plain HTTP
origin and a reachable mirror URL in your own environment.

Mirror:

```bash
curl -i --proxy http://127.0.0.1:8787 http://your-origin.example/
```

Expected:

- `x-anymirror-example-action: mirror`
- `x-anymirror-target` points to your configured `mirror_url`

Direct:

```bash
curl -i --proxy http://127.0.0.1:8787 http://your-origin.example/ -H "x-anymirror-example: direct"
```

Expected:

- `x-anymirror-example-action: direct`
- `x-anymirror-target` points to the original request URL

Reject:

```bash
curl -i --proxy http://127.0.0.1:8787 http://your-origin.example/ -H "x-anymirror-example: reject"
```

Expected:

- HTTP `451`
- body contains `rejected by example plugin`

## Explicit Mode HTTPS Note

The explicit proxy build now intercepts HTTPS proxy traffic after HTTP `CONNECT`, so the example
plugin can inspect and rewrite HTTPS requests too once the AnyMirror CA is trusted.

Commands like this can work for HTTPS validation once the client trusts `anymirror_ca.crt`:

```bash
curl -i --proxy http://127.0.0.1:8787 --cacert anymirror_ca.crt https://your-origin.example/
```

This example still uses `http://...` for the quickest explicit-mode verification flow.
