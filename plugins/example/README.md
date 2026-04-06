# Example Plugin

This example is intentionally small and easy to verify.

It demonstrates:

- `on_load`: read plugin config
- `on_compile`: compile one default `mirror` rule
- `on_request`: switch the compiled action with a request header
- `on_response`: add visible response headers

It does **not** request body permissions, so it stays on the lightweight plugin path.
It is easiest to validate in **explicit proxy mode** with a single public echo service.

## Suggested Config

```yaml
listen: 127.0.0.1:8787

plugins:
  enabled: true
  workers: 4
  includes:
    - name: example
      config:
        host: httpbin.org
        mirror_url: https://httpbin.org/anything/mirror
        control_header: x-anymirror-example
        response_header: x-anymirror-example

includes:
  - match:
      host: httpbin.org
    action:
      type: plugin
      name: example
```

## Behavior

The compiled default action is:

- match `host = httpbin.org`
- action `mirror -> https://httpbin.org/anything/mirror`

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

Mirror:

```bash
curl -i --proxy http://127.0.0.1:8787 https://httpbin.org/anything/original
```

Expected:

- `x-anymirror-example-action: mirror`
- `x-anymirror-target: https://httpbin.org/anything/mirror`
- JSON body URL/path points to `/anything/mirror`

Direct:

```bash
curl -i --proxy http://127.0.0.1:8787 https://httpbin.org/anything/original -H "x-anymirror-example: direct"
```

Expected:

- `x-anymirror-example-action: direct`
- `x-anymirror-target: https://httpbin.org/anything/original`
- JSON body URL/path stays on `/anything/original`

Reject:

```bash
curl -i --proxy http://127.0.0.1:8787 https://httpbin.org/anything/original -H "x-anymirror-example: reject"
```

Expected:

- HTTP `451`
- body contains `rejected by example plugin`
