# AI assistance through an internal model

OTInspect can ask a language model to help interpret a scan: an executive summary, a prioritised
remediation plan, an IEC 62443-3-3 view, likely attack paths, an explanation of one finding, or a free
question. It is **off by default** and meant for **models your organisation runs or controls**: a
[LiteLLM](https://github.com/BerriAI/litellm) AI gateway, vLLM, Ollama, LM Studio, LocalAI, TGI or an
Azure OpenAI private endpoint.

The scan itself does not change. It still only reads files, never connects to devices and never
contacts the AI endpoint. Only an explicit AI request does, with pseudonymised data.

## Quick start

**GUI**: *AI settings…* → fill in *Base URL* and *Model* → *API key* tab → *Test connection* → *Save*.
Scan a folder, open the *AI Assistant* tab, choose a task and *Run analysis*. Right-click a finding →
*Explain with AI…*.

**CLI**:

```bash
otinspect ai init                         # writes ~/.otinspect/ai_profiles.json (template, no key)
# edit base_url and model, then provide the key:
export OTINSPECT_AI_API_KEY=sk-...        # Windows: $env:OTINSPECT_AI_API_KEY="sk-..."
otinspect ai test                         # policy, TLS, key, /models and a one-word chat
otinspect scan D:\Backup --json report.json
otinspect ai analyze report.json --task prioritise --lang vi -o plan.md
otinspect ai analyze report.json --task question --question "Which hosts can stop PLCs?" --preview
```

`--preview` prints exactly what would be sent and sends nothing. Tasks: `summary`, `prioritise`,
`iec62443`, `attack_paths`, `question` (and `explain` in the GUI).

## Profile reference

Profiles live in `~/.otinspect/ai_profiles.json` (override with `OTINSPECT_AI_CONFIG`). The file is
written with owner-only permissions and **never contains an API key**. A profile containing `api_key`,
`token`, `password` or `secret` is rejected.

| Field | Default | Purpose |
|---|---|---|
| `provider` | `litellm` | `litellm`, `openai_compatible` or `azure_openai` |
| `base_url` | | API root, e.g. `https://llm-gateway.internal.example/v1` (LiteLLM / vLLM / Ollama: ends with `/v1`; Azure: `https://<resource>.openai.azure.com`) |
| `model` | | Model alias on the gateway, or the Azure deployment name |
| `azure_api_version` | `2024-10-21` | Azure only |
| `secret_store` | `env` | Where the key comes from: `keyring` (OS keyring, needs `pip install keyring`), `env`, or `session` (memory until the GUI closes) |
| `api_key_env` | `OTINSPECT_AI_API_KEY` | Variable name for `env` |
| `user_tag` | | Sent as the OpenAI `user` field: LiteLLM uses it for spend tracking and audit |
| `extra_headers` | `{}` | Non-secret headers, e.g. `x-litellm-tags`. `Authorization`, `api-key`, `Cookie` and similar are refused |
| `timeout_s`, `max_tokens`, `temperature` | 60, 1500, 0.2 | Request settings |
| `verify_tls` | `true` | Certificate verification. TLS 1.2 is the minimum |
| `ca_bundle` | | Internal CA certificate (PEM) |
| `client_cert`, `client_key` | | Mutual TLS, if the gateway requires it |
| `proxy` | | Explicit proxy. Empty means a direct connection: `HTTP(S)_PROXY` from the environment is **ignored** |
| `allow_http` | `false` | Plain HTTP is refused except for loopback, unless this is set (lab only) |
| `internal_only` | `true` | Refuse endpoints that resolve to a public IP address |
| `allowed_hosts` | `[]` | Exceptions to `internal_only`, e.g. `*.openai.azure.com` behind a private endpoint |
| `mask_ips`, `mask_macs`, `mask_names`, `mask_paths`, `mask_secrets` | `true` | Data minimisation, see below |
| `max_findings`, `max_assets`, `max_prompt_chars` | 150, 150, 60000 | Upper bounds on what is sent |
| `confirm_before_send` | `true` | GUI shows the full payload and asks before every request |
| `audit_log`, `audit_log_path` | `true`, `~/.otinspect/ai_audit.jsonl` | Metadata-only audit trail |

## Security controls

| Risk | Control |
|---|---|
| Sensitive topology leaves the site | Only findings and asset attributes are sent, with limits. The scanned path, file hashes, file contents and raw captures are never sent. IPs, MACs, asset/host names, file names and e-mail addresses become stable pseudonyms (`IP-3`, `ASSET-7`, `FILE-2.scd`). The mapping stays in memory on this computer and real values are put back into the answer locally |
| Credentials in configs reach the model | Passwords, SNMP communities, PSKs, private keys, bearer tokens, JWTs and API keys are replaced by `[SECRET]` and never restored |
| Data sent to a public or wrong service | `internal_only` checks every resolved address before each request (RFC 1918, CGNAT, ULA, loopback and link-local count as internal). Redirects are refused. System proxies are ignored unless one is configured |
| Interception | HTTPS required, TLS 1.2+, certificate verification on, internal CA and mTLS supported |
| API key leakage | Key from the OS keyring, an environment variable or memory, never in the profile file, logs, exports or error messages |
| Prompt injection from scanned files | File-derived text is wrapped in delimiters with a per-request random ID; the system prompt tells the model to treat it as untrusted data. The answer is shown as plain text (never rendered as HTML) and does not trigger any action |
| Hallucination | Prompts require answers grounded in the data with rule IDs cited, no invented CVEs, process-safe recommendations. Answers are labelled decision support |
| Accountability | Audit log: time, OS user, profile, endpoint host, model, task, status, prompt SHA-256, sizes, token usage. No prompt or answer content |
| Oversized or hostile responses | Response capped at 4 MB, strict JSON parsing, timeouts |

Saved answers contain the real identifiers again: handle them like the reports, as confidential.

## LiteLLM gateway checklist

On the gateway side, give OTInspect its own **virtual key** limited to the approved model(s), with a
budget and rate limit, and turn on guardrails / PII masking and logging policies that fit your data
classification. Use `user_tag` or `x-litellm-tags` to tell OTInspect traffic apart in spend and audit
logs. Check that the gateway itself does not forward prompts to an external provider unless that is
approved for OT data.
