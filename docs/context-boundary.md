# Model context boundary

All application-owned system messages are constructed by
`agent/core/context_builder.py`. Callers choose a reviewed policy id; there is no
argument accepting arbitrary system/developer text. Fixed policy text lives in
`agent/prompts/context_policies.py` or the existing reviewed prompt packs.

```python
messages = build_context(
    "agent",
    user=user_content,
    history=state.get("messages", []),
    preferences=profile.system_prompt,
    data=[ContextBlock("browser", browser_snapshot)],
)
```

## Contract

- Application instructions are rebuilt on every invocation. A system message in
  history cannot suppress or replace them.
- Restored system/developer messages become `context_data` reference messages.
  This also applies to old checkpoints containing privileged memories/summaries.
- Agent profile `system_prompt` is a user-level preference, not a platform rule.
- Evidence, memories and summaries are JSON-serialized `context_data` messages;
  content cannot create message roles. Labels guide the model but are not an
  execution authorization boundary.
- The current user task follows reference data so tool selection sees the task.
- Assistant/tool messages preserve ids, tool-call linkage and multimodal content.
- Provider adapters may add fixed safety instructions. Server-configured framework
  middleware (for example the todo middleware) remains trusted infrastructure.
  Remote tool descriptions are reference data, including in JSON-mode selection.
- Isolation is unconditional and does not depend on `security_enabled`.

`tests/test_context_architecture.py` rejects direct privileged constructors,
role dictionaries and role templates outside the approved boundary modules.
`tests/test_context_boundary.py` checks provider payloads and the summary, agent,
support and selector paths without calling a remote model.

## Follow-up work

This change addresses privileged context construction. The following are separate
work items, not guarantees provided by message roles:

- Persist source lineage and sensitivity labels across storage and derived data.
- Split legacy user-only research/optimizer templates into task and evidence fields.
- Complete task-scoped authorization and data egress restrictions at execution.
- Evaluate injection resistance with live models and bounded adversarial fixtures.

Never put credentials in any prompt. Keep tool permission checks outside the model.
