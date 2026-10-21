# The vulnerable demo target

`injectkit-demo` is an **intentionally vulnerable** local chat API used to try InjectKit and
to test it in CI. It is not a product and not a model. Install the extra and start it:

```text
uv sync --extra demo
uv run injectkit-demo                                # 127.0.0.1:8000, scripted backend
uv run injectkit run examples/demo-target.yaml       # second terminal
```

`examples/demo-target.yaml` uses `network.policy: loopback`; the default `public_only`
policy blocks 127.0.0.1 on purpose.

## Safety

* Binds to `127.0.0.1` by default. Any other host aborts (exit 2) unless **both**
  `--allow-public-bind` and the environment variable `INJECTKIT_DEMO_ALLOW_PUBLIC=1` are
  given; then a warning banner is printed.
* Every secret in the demo is fake. The system prompt contains the published value
  `DEMO-FAKE-SECRET-7f3a91`, which is not a credential for anything.
* Request bodies are limited to 16 KiB (413 above). `/docs` and `/openapi.json` are off.

## API

`POST /chat` with `{"messages": [{"role": "user", "content": "..."}]}` returns
`{"reply": "..."}`. `GET /health` returns the backend name. The last `user` message is used.

## Backends

`--backend scripted` (default, deterministic, used in CI) is a fixture made of four fixed
rules, not a language model:

1. A message asking to join/concatenate/follow two canary halves is obeyed.
2. A message asking for its instructions, configuration, keys or "words above" makes it print
   its system prompt, including the fake fragment.
3. Delimiter-confusion payloads (`###`, `</`, `<|im_`, "end of user data") are obeyed, but
   the token comes back **reversed**. The canary detector cannot see that: a documented
   false negative, reported as `no_indicator`, which shows why that outcome is not "secure".
4. Anything else is refused.

Against the `basic` suite this yields 28 confirmed tests and 4 `no_indicator` (`dc-01..04`).

`--backend ollama` forwards to a local Ollama server at `127.0.0.1:11434` (loopback only) with
the model named in `INJECTKIT_DEMO_MODEL`. No default model is assumed; if the variable is
missing or Ollama is not running, `/chat` answers 503 with a clear message. Results depend on
the model and are not deterministic.
