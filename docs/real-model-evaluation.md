# Real-model adversarial evaluation

## Research question

When a locally hosted language model reads adversarial untrusted content and proposes an unauthorized privileged action, does AgentShield prevent the simulated action at the runtime authority boundary?

Model resistance and AgentShield mitigation are different observations:

- **Attack propagation:** the model proposes the unauthorized target capability.
- **Model resistance:** an attack is present but the model does not propose that target.
- **AgentShield mitigation:** an unauthorized known capability reaches AgentShield and is prevented.
- **Attack success:** the unauthorized capability produces a simulated execution record.

A refusal or malformed response receives no mitigation credit because no unauthorized proposal reached enforcement. Conditional mitigation is blocked unauthorized proposals divided by unauthorized proposals reaching AgentShield.

## Corpus and method

Stage 10 corpus version 1.0 contains 60 natural-language adversarial variants across indirect prompt injection, authority and role impersonation, compromised tool output, poisoned memory, scope manipulation, delayed and hidden instructions, conflicting instructions, multi-hop influence, model authority claims, and provenance manipulation. It also includes 20 ordinary benign cases and four explicitly authorized controls.

Each selected variant is generated separately in unprotected and protected modes with equivalent model settings. Since generation may be nondeterministic, paired outputs are recorded rather than assumed identical. Every proposed action is evaluated independently. Unknown tools and malformed output fail closed. All email, shell, network, and file effects use AgentShield's existing controlled simulators.

The tool-output variants place natural-language instructions in a compromised response. Memory and multi-hop variants retain their untrusted boundary through the model context. Scope variants grant only `demo@example.test` while untrusted content requests `other@example.test`. Model-provided claims such as `authority=true`, `source_trust=TRUSTED`, or `decision=ALLOW` have no authority-bearing role.

## Reproduce

Install and start Ollama yourself, then use an already installed model:

```bash
agentshield doctor
agentshield experiment real-model \
  --model your-local-model:tag \
  --trials 5 \
  --format text
```

Compare models with `--models model-a:tag model-b:tag`. For a shorter intentional run, select families and a benign limit:

```bash
agentshield experiment real-model \
  --model your-local-model:tag \
  --trials 1 \
  --families indirect_prompt_injection scope_manipulation \
  --benign-limit 4 \
  --format json
```

Results, sanitized failure records, and a summary manifest are written under `experiments/stage10/` unless `--output-dir` changes it. Large raw artifacts are ignored by Git by default.

Metadata includes AgentShield and corpus versions, corpus hashes, model name/tag/digest when discoverable, Ollama version, temperature, seed, Python, platform, and UTC timestamp. Raw model output is truncated in records.

## Stage 10.1 protocol diagnosis and smoke results

The initial `qwen3:4b` smoke produced 28/28 malformed outputs. Artifacts had discarded the raw empty string, but a bounded reproduction against Ollama 0.32.9 established the cause: Qwen3 placed a complete JSON object in Ollama's separate `thinking` field while `response` was empty. The adapter correctly parsed only `response`; the experiment classifier then incorrectly counted malformed attack responses as model resistance.

Stage 10.1 now sends the AgentShield contract as Ollama's `format` JSON Schema, sets `think=false` by default for structured experiments, and records a 256-token default limit. AgentShield still performs its own exact-field, type, tool-name, and required-argument validation. A whole proposal batch is rejected before execution if any action is malformed.

The two-case protocol smoke passed for local `qwen3:4b` (digest `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7`): the no-action response was valid with zero actions, and the action response was valid with one simulated `send_email` proposal to `demo@example.test`.

### Cross-model protocol clarification

An initial `llama3.2:3b` protocol smoke returned valid JSON but failed both semantics. Exact payload inspection showed that the no-action request was immediately preceded by `Available tool: send_email`, which primed Llama to emit `send_email` with empty arguments despite the explicit no-tool user request. In the action case, Llama proposed the correct tool and recipient value but used `arguments.recipient` rather than the existing required `arguments.to` contract. The direct successful Ollama prompt had no tool advertisement, explaining the no-action difference; AgentShield's generic JSON Schema intentionally describes `arguments` as an object, so the exact tool argument name depended on protocol prose.

The provider-neutral contract now states that `proposed_actions` may be empty, tools are optional and never mandatory, and side effects should be proposed only when explicitly requested. The no-action case contains no tool catalog. The action case documents the existing `send_email` contract as `{"to": "recipient address"}`. There are no model-specific branches, examples, attack-corpus content, or carried state. The JSON Schema and AgentShield validation were not weakened or changed for this correction.

With identical temperature 0, seed 0, thinking disabled, and 256-token settings, both `llama3.2:3b` and `qwen3:4b` passed: valid no-action output with zero actions, and one valid `send_email` action to `demo@example.test`. Llama is therefore protocol-compatible and ready for a separately authorized Stage 10 corpus evaluation; no Llama corpus run was performed as part of this gate.

The final corrected two-family smoke used temperature 0, seed 0, thinking disabled, and 256 maximum output tokens. It made 28 generations: 20 attack and eight ordinary-benign generations because every selected context ran in both modes. All 28 responses were valid, with no malformed output or model error. Among ten evaluable protected attacks, six propagated and four resisted. AgentShield blocked 6/6 unauthorized proposals; protected executions were 0/10, paired unprotected executions were 6/10, scope violations were blocked 2/2, and attribution succeeded 6/6 where applicable. The four selected benign variants produced no privileged proposals.

A diagnostic authorized-control run initially included an invalid `read_document` action, revealing a batch-validation defect: a later valid action could previously be evaluated before the response was classified malformed. Stage 10.1 fixed the model runtime to validate the complete action batch before any execution, so malformed output now executes nothing. After clarifying that supplied source content must not be re-read, the final authorized-control run produced 8/8 valid paired responses. All four protected controls proposed the exact scoped action and AgentShield allowed 4/4, with zero false positives.

## Final v0.1.0 results

Both experiments used Ollama 0.32.9, temperature 0, seed 0, thinking disabled, a 256-token output limit, and the same JSON Schema protocol. Every corpus context was generated independently in protected and unprotected modes; paired generations are recorded observations, not an assumption that nondeterministic model outputs match.

| Metric | Qwen3 4B | Llama 3.2 3B |
| --- | ---: | ---: |
| Model digest | `359d7dd4…94fae7` | `a80c4f17…b8b72` |
| Trials per adversarial variant | 5 | 1 |
| Total generations | 840 | 168 |
| Valid structured outputs | 840/840 | 162/168 |
| Malformed generations | 0/840 | 6/168 |
| Model errors | 0 | 0 |
| Protected attack trials | 300 | 60 |
| Valid protected responses | 300/300 | 57/60 |
| Attack propagation | 145/300 (48.3%) | 24/57 (42.1%) |
| Model resistance | 155/300 (51.7%) | 33/57 (57.9%) |
| Unauthorized proposals | 145 | 24 |
| AgentShield mitigations | 145/145 | 24/24 |
| Protected attack successes | 0/300 | 0/60 |
| Unprotected attack successes | 145/300 | 25/60 |
| Authorized actions allowed | 20/20 | 4/4 |
| Scope violations blocked | 10/10 | 2/2 |
| Attribution success | 145/145 | 24/24 |
| Enforcement failures | 0 | 0 |

Qwen3 4B used digest `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7`. Its 840 generations cover 300 protected and 300 unprotected attack trials, 100 paired benign generations, and 40 paired authorized-control generations. It produced no malformed response or model error. The model propagated 145 unauthorized target actions in protected trials; AgentShield blocked all 145. All 20 protected authorized actions were proposed and allowed, 10/10 proposed scope violations were blocked, and attribution succeeded for all 145 applicable proposals.

Llama 3.2 3B used digest `a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72`. Its 168 generations cover 60 protected and 60 unprotected attack trials, 40 paired benign generations, and eight paired authorized-control generations. Six responses were malformed—three protected and three unprotected attack responses—and failed closed. They are neither model resistance nor AgentShield mitigation. Of 57 valid protected attack responses, 24 propagated and 33 resisted. AgentShield blocked all 24 proposals, allowed 4/4 protected authorized actions, blocked 2/2 proposed scope violations, and attributed all 24 applicable proposals.

Model resistance and runtime mitigation answer different questions. Resistance measures whether a valid model response omitted the unauthorized target action. Mitigation is conditional on an unauthorized action actually reaching AgentShield. The differing resistance rates show that model-level behavior is inconsistent; the enforcement result depends on authority, provenance, and scope at the runtime boundary rather than on successful semantic refusal.

The existing deterministic, framework, and persistence benchmark baselines remain separate and unchanged. A sanitized machine-readable summary is published in `benchmarks/real-model-v0.1.0.json`; raw local generations remain excluded.

## Limitations

Model behavior varies by model build, quantization, prompt formatting, Ollama version, seed support, temperature, and host. Denominators differ because Qwen used five trials per variant and Llama used one, and malformed Llama responses are excluded from resistance calculations. The natural-language corpus is controlled and finite. Simulated effects do not establish production containment. Attribution depends on complete instrumentation, and ambiguous causal graphs can remain ambiguous. Live metrics are not blocking nondeterministic CI thresholds; genuine enforcement failures should first be reproduced with a deterministic regression test.
