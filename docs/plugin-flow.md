# Plugin Flow

This document explains the current plugin request and response flow for `on_load`, `on_compile`,
`on_request`, and `on_response`.

## Example Scenario

Assume a plugin compiles a rule whose default action is:

- `mirror`
- mirror upstream response body: `i am mirror`

At runtime, `on_request` may override that compiled action to:

- `direct`
- original upstream response body: `i am direct`

## Lifecycle

```text
Config Load / Runtime Reload
    |
    v
on_load(config)
    |
    v
plugin state
    |
    v
on_compile(config + state)
    |
    v
program.rules
```

## Request / Response Flow

```text
Incoming Request
    |
    v
Main Rule Engine
    |
    +-- no plugin rule matched
    |      |
    |      v
    |   normal mirror/direct/reject flow
    |
    `-- plugin rule matched
           |
           v
      Build PluginRequestContext(request)
           |
           v
      Match plugin program.rules
           |
           +-- no plugin program rule matched
           |      |
           |      +-- no on_request or on_request returns null
           |      |      |
           |      |      v
           |      |   resolved_action = direct
           |      |
           |      `-- on_request returns action override
           |             |
           |             v
           |          resolved_action = returned action
           |
           `-- plugin program rule matched
                  |
                  v
             matched.action = compiled action
                  |
                  +-- no on_request or on_request returns null
                  |      |
                  |      v
                  |   resolved_action = matched.action
                  |
                  `-- on_request returns action override
                         |
                         v
                      resolved_action = returned action
```

## Upstream Branches

```text
resolved_action
    |
    +-- reject
    |      |
    |      v
    |   return local reject response
    |   on_response does not run
    |
    +-- direct
    |      |
    |      v
    |   send request to original upstream
    |      |
    |      v
    |   upstream response body = "i am direct"
    |      |
    |      v
    |   on_response(request, matched, resolved_action=direct, response)
    |
    `-- mirror
           |
           v
        send request to mirror upstream
           |
           v
        upstream response body = "i am mirror"
           |
           v
        on_response(request, matched, resolved_action=mirror, response)
```

## Data Visible To `on_response`

`on_response` currently receives:

- `request`
  - The final request view after `on_request` request patches have been applied.
- `matched`
  - The original compiled plugin rule match.
- `resolved_action`
  - The final action that was actually executed after any `on_request` override.
- `response`
  - The buffered upstream response seen before the final response is returned to the client.

This means `on_response` can distinguish:

- what the compiled plugin rule originally wanted to do
- what `on_request` changed it into
- what the upstream actually returned

## Mirror -> Direct Override Example

```text
Compiled plugin rule:
    matched.action = mirror

on_request condition matched:
    resolved_action = direct

Actual upstream path:
    original upstream -> "i am direct"

on_response sees:
    matched.action   = mirror
    resolved_action  = direct
    response.body    = "i am direct"
```
