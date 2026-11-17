# The LLM layer

`candix.llm` is a small provider-agnostic client with the pieces a security agent needs:
streaming, tool calls, caching, token accounting, schema validation and redaction.

## Providers

| Provider | Class | Transport |
| --- | --- | --- |
| OpenAI-compatible | `OpenAICompatibleProvider` | `/chat/completions` |
| Anthropic | `AnthropicProvider` | `/v1/messages` |
| Ollama | `OllamaProvider` | `/api/chat` |

A `Provider` is anything with `complete(request)` and `stream(request)`. The client tries
providers in order and fails over on transport or authentication errors, not on content
errors.

```python
from candix.llm import LLMClient
from candix.llm.providers import OllamaProvider

client = LLMClient([OllamaProvider(model="llama3.1")])
answer = client.complete("summarise this response", task="reflect")
```

## Cost control

`UsageLedger` tracks prompt tokens, completion tokens and cost per task and enforces
`LedgerLimits`. `estimate_request` gives a pre-flight estimate using a character heuristic
that overestimates slightly on purpose: hitting a limit before spending money is better
than after.

`ResponseCache` keys on the canonical request (model, messages, tools, temperature) so an
identical planning prompt in the same run is free the second time.

## Tool calls

`complete_with_tools` sends `ToolSpec` definitions and returns `ToolCall` objects. Local
models often answer with text instead. `llm.toolcall.parse` recovers:

- a JSON object `{"tool": ..., "arguments": {...}}`
- a JSON array, or an object with `tool_calls`
- XML blocks `<function=name><parameter name="x">1</parameter></function>`
- ReAct lines `Action: name` / `Action Input: {...}`

Every recovery is counted (`worker.recovered_tool_calls`) so a flaky model is visible in
telemetry rather than silently degrading the run.

## Validation

`llm.jsonschema` validates model output against a schema and coerces scalars. It tolerates
fenced JSON, trailing commas and truncation, because rejecting a correct plan over a
missing brace wastes a turn.

## Redaction

`Guardrails` runs before anything is sent to a model:

- 15 secret patterns (cloud keys, tokens, JWTs, private keys, cookies, passwords,
  connection strings)
- the core redaction policy for engagement-specific patterns
- deny phrases that make a prompt unsendable, and a size ceiling

Tool output is redacted *after* the tool ran, before it enters the message list, so the
model never sees a session cookie even though the tool needed it.

## Prompts

`llm.prompts` holds the system, planner, worker, reflection and triage templates with
versions and declared variables. `render(name, **values)` raises on a missing variable
instead of sending `{goal}` to the model. `validate_all()` is covered by tests.

## Embeddings

`llm.embeddings` provides hashed token vectors, character n-gram vectors and cosine
similarity with no external dependency. It powers lesson retrieval, skill selection and
finding de-duplication. `cluster()` groups near-duplicate strings so three copies of the
same XSS are reported once.

## Conversation state

`Conversation` holds the message list under a token ceiling. `compact()` shrinks
old tool output first, then assistant prose, then the user turn, and finally the
summary itself, so a long run degrades instead of failing. `fork`, `pin` and
`drop_tools` cover retries and tool-list changes mid-run.

`agentic` parses Thought/Action/Observation/Final text, checks whether a step is
actionable with the current tool list, narrows an over-broad step (`narrow`),
repairs a plan against the tool registry (`repair_plan`) and critiques a final
answer against the evidence references it cites.

## Recovering bad responses

`repair.repair_json` walks a ladder: strip the code fence, drop comments, remove
trailing commas, normalise `True/False/None`, convert single quotes, quote bare
keys. `repair_action` and `repair_arguments` then map the result onto the tool
registry, dropping unknown keys and recovering a tool name mentioned in prose.
`coerce_*` helpers turn "42%", "yes" and "a, b" into usable values.

## Choosing a tool and voting

`tool_router` scores registry entries against the intent text using keyword
tables, a phase fit and a cost penalty, and returns the ranked choice with the
reasons attached. `fallback_chain` gives the planner alternatives for a retry.

`voting` asks the model several times and keeps the weighted majority:
`from_tool_calls`, `choose_tool` with a minimum agreement, and
`consensus_json` which votes field by field so one bad field does not sink an
otherwise good answer.

## Calibration

`calibration` measures whether confidences mean anything: Brier score, expected
calibration error, reliability bins, precision/recall at a threshold and a
threshold picker. `Calibrator` fits a monotone mapping with pooled adjacent
violators and can be saved next to the run, so tomorrow's confidence uses
yesterday's outcomes.

## Attachments

`attachments` loads operator files under a token budget: kind sniffing, HTML to
text, secret redaction, truncation marks, chunking with overlap, HAR extraction
and a `{{env:...}}`-free prompt block. `AttachmentSet.trim()` drops the largest
items until the set fits.
