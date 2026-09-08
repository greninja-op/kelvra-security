# Kelvra Security Report — Update: Web, Mobile & Connection Security

> **Review cadence (binding):** automated MASVS / dependency / secret-scan checks on **every CI build**;
> full manual review **quarterly or every major release, whichever comes first**.
> Next manual review due: **2026-12-08**.
> **Freshness rule:** any task touching auth, storage, network/transport, crypto, new
> dependency/MCP connector/plugin/skill, or new external integration MUST update the relevant
> section below **in the same commit** (enforced by Steering rule `rule-security-report-freshness`,
> §6). A report one release behind the code is close to worthless.

- **Status:** findings from live code audit, 2026-09-08. Severities: Critical / High / Medium / Low.
- **Scope of this update:** Bench web UI (OWASP Top 10:2025), Bench REST/WebSocket API
  (OWASP API Top 10 2023), Kelvra Mobile (OWASP MASVS), Mobile↔Bench transport, messaging webhooks.
- **Out of scope (unchanged):** the existing OWASP LLM/Agentic Top 10-grounded section stays as-is
  and is not reproduced here.
- **Trust-model decision (§4.5) is OPEN** — documented as undecided, not assumed. Do not build
  against an assumed answer.

---

## 1. Web — Bench UI & API per OWASP Top 10:2025

### A01 Broken Access Control — Critical
- **Risk for Kelvra:** every Bench endpoint (`/api/terminals/*`, `/api/sessions/*`,
  `/api/workspace/*`, `/ws/swarm`) resolves the target by bare ID with no caller principal.
  `terminal_manager.get_session()` is a pure dict lookup
  (`kelvra-bench/src/terminal_manager.py:275-276`); workspace/steering/artifact lookups filter by
  URL-segment equality only. Any LAN caller can pause/resume/delete/duplicate/respond on any
  session (`agent-frontend`, `agent-pane-XXXX`) just by naming it — textbook BOLA/IDOR.
  `GET /api/git/graph?workspace_id=` falls back to `BASE_DIR` when omitted
  (`kelvra-bench/src/server.py:830-843`); `POST /api/workspaces` accepts an attacker-controlled
  `path` that later becomes a `cwd` for git subprocesses (`server.py:799-824`,
  `git_graph_service.py:29-46`). Artifacts ignore the `chat_id` path param (cross-chat read,
  `server.py:3168-3197`). `/ws/swarm` accepts without token and honors `SEND_INPUT` /
  `MOVE_KANBAN` from any peer (`server.py:3227-3277`).
- **Fix:** bind `127.0.0.1` by default (today `0.0.0.0:8099`, `server.py:3292-3294`); bearer-token
  middleware; per-workspace ACL + unguessable session IDs + ownership check on every
  `{session_id|workspace_id|chat_id|agent_id}` parameter.

### A02 Security Misconfiguration — High
- **Risk for Kelvra:** FastAPI app has no auth middleware, no CORS/TrustedHost policy
  (`server.py:141-144`); Security service ships `allow_origins=["*"]` **with**
  `allow_credentials=True` (`kelvra-security/src/api.py:25-31`) plus 13 undocumented endpoints
  (README documents 3). Every surface added since the original report is unaudited for defaults:
  workspace config panel defaults everything ON and global (filesystem MCP
  installed+connected, all 5 skills enabled — `extensibility_manager.py:258-294`), seeded hooks
  auto-dispatch with no screening gate, browser pane has no URL/SSRF policy
  (`browser_manager.py:105-128` only prepends `https://`; `about:`/metadata IPs allowed),
  `DEBUG` flag is env-controlled (`config.py:19`), release mobile build still points at debug
  signing config.
- **Fix:** default-deny on MCP/hooks/skills (explicit per-workspace enable); URL allowlist for
  browser/git paths (deny `169.254.169.254`, loopback, RFC-1918, `file:`, `about:` except allowlist);
  CORS allowlist (never `*` + credentials); `DEBUG=false` enforced in prod with an exception
  handler that strips paths.

### A03 Software Supply Chain Failures — High (highest-relevance new category for Kelvra)
- **Risk for Kelvra:** MCP servers/connectors, Plugins (auto-enable bundled MCP+skills without
  re-consent, `extensibility_manager.py:500-568`), user-uploaded SKILL.md files, and the
  `browser-use` integration are all live trust boundaries. Skill upload
  (`server.py:2025-2044` → `extensibility_manager.upload_skill():614-669`) calls **neither**
  `security_client.screen_skill()` **nor** `MCPSkillScanner.scan_skill_content()` (both exist,
  both unwired — scanner checks injection/zero-width/base64/reverse-shell/Lethal-Trifecta,
  `ward/mcp_skill_scanner.py:113-157`); content is trusted instantly, `enabled=True`, no size
  cap, and flows straight into agent prompts via steering context (stored prompt-injection).
  MCP connect accepts arbitrary `server_id|url|transport|api_key` with no URL allowlist, no SSRF
  guard, no `authorize_mcp()` pre-exec; `stdio` catalog entries (`npx -y …`) are RCE-equivalent
  if spawned. Steering/hook/agent text is saved with no screening and no length caps
  (`steering_manager.py:193-218,246-270,338-362`).
- **Fix:** wire `scan_skill_content()` + `screen_skill()` as a **blocking** upload gate plus the
  existing (opt-in, never-called) `/api/ward/mcp-skill/scan` + `safe-install` sandbox;
  URL/transport allowlist + `authorize_mcp` before every tool exec; screen all steering/hook/agent
  text. **Static scanning is known-insufficient** (100k-blank-line truncation bypass in Ward's
  spec) — this section points to Ward's runtime/eBPF layer as the real mitigation, not the
  pre-scan.

### A04 Cryptographic Failures — High
- **Risk for Kelvra:** provider keys fall back to `data/.vault.enc` = base64(XOR(json,
  `COMPUTERNAME-USERNAME-…-salt`)) — reversible obfuscation, world-readable, predictable salt
  (`kelvra-bench/src/auth/credential_vault.py:51-66`); `keyring` is missing from Security's
  `requirements.txt`, guaranteeing the fallback path on fresh installs. Bench dual-writes keys in
  **plaintext** to `~/.fcc/.env` + process env (`provider_manager.py:156-166,189-204,289-294`).
  Gemini key is embedded in query strings (`?key={key}`, `provider_manager.py:375,460`) — logged
  by proxies. Mobile↔Bench transport is cleartext by default (no TLS on `:8099`, §4).
- **Fix:** OS DPAPI/LibSecret or AES-GCM with random salt; `chmod 600`; eliminate the `.env`
  plaintext mirror; never put keys in URLs; TLS floor per §4.6.

### A05 Injection / API7 SSRF — High
- **Risk for Kelvra:** swarm agents execute real shell commands and outbound requests (worse once
  the browser pane is live). `PromptGuard` is regex-only (`prompt_guard.py:16-65`), sanitization
  is `.strip()` (no redaction), and dispatch-path screen failures return silently with **no audit
  event** (`server.py:253-259,2782-2788`) — injection payloads can be probed invisibly.
  `deny_dangerous` covers a subset; `argument` inspection is absent in `mcp_authorizer`
  (`tool_args` accepted but ignored, `mcp_authorizer.py:91-143`).
- **Bounds that do hold:** `/screen` pre-dispatch + `/audit` pre-`COMPLETED` + worktree-per-agent
  isolation (blast radius is per-worktree, merge-gated). **Gaps if screening is passed:**
  unscreened hook `action_prompt`s dispatch through the same `/ws/swarm` channel
  (`server.py:2290-2309`); TTS PowerShell interpolation is incompletely escaped
  (backtick/`$()` — `tts_engine.py:247-255`); attacker-influenced strings are vocalized verbatim
  (`server.py:744-748`, `talkback` history unredacted).
- **Fix:** log every `is_safe==False` with payload-hash (never raw secret); screen hook/steering
  prompts through the same gate; `-EncodedCommand`/arg-list for TTS synthesis; redact before
  `Talkback.say` and before logs.

### A06 Insecure Design — Medium (process)
- **Risk for Kelvra:** the confirmation gate — the single control standing between a voice/text
  instruction and a destructive action — is unauthenticated end-to-end: `POST /gate/confirm`
  accepts bare `ui_click` with no token/session binding (`confirmation_gate.py:139-143`), typed
  approval is a static global (`CONFIRM|YES|APPROVE`, `:90,147`), challenge IDs are 32-bit
  (`gate-{uuid4hex[:8]}`, `:88`), `GET /gate/challenges` + `GET /audit-logs` leak live PINs/tokens
  (`api.py:341-344,430-442`; live evidence in `data/security_audit.jsonl`), and `POST /gate/cancel`
  is an unauthenticated DoS on legitimate gates (`:334-338`). Chat-channel confirmations
  (`confirm`/`yes` text) bypass the `security_client` challenge entirely
  (`intent_router.py:238-268`).
- **Fix:** challenge bound to session+channel with single-use token, no static accept strings,
  no PIN/token in logs or list endpoints, chat confirms bound to `security_client` challenge IDs.

### A07 Authentication Failures / API2 — High
- **Risk for Kelvra:** two parallel auth worlds with no policy between them — CLI-subscription
  trust is **file-existence** (`~/.claude/credentials.json` ⇒ `SIGNED_IN`,
  `cli_auth_detector.py:56-116`; antigravity/git hard-coded), direct-key path has no
  "CLI already signed in — refuse key" (or vice-versa) check (`server.py:2408-2424`), and proxy
  resolution (`env` → `os.environ` → vault, `server.py:2572-2575`) lets a `~/.fcc/.env` write
  silently override the vault/CLI path. `trigger_login()` shells out without an allowlist
  (`cli_auth_detector.py:123-153`). Voice/messaging commands must clear the **same** bar as typed
  ones: today the barge-in channel (`abort_speech`) and `permission_resolved` ride a one-time
  connect-time token check with no per-message auth, no device binding, no biometric proof
  (`mobile_bridge.py:292-347`), and voice alone is (correctly, per standing rule) never sufficient
  for destructive actions — the gate in A06 must actually enforce that.
- **Fix:** `auth_mode={cli|key|offline}` per provider with explicit precedence + audit on switch;
  `cli_id` allowlist; per-message auth + device binding on the mobile/voice control channels.

### A08 Software/Data Integrity Failures — High
- **Risk for Kelvra:** Mobile update manifest falls back to `{sha256:000…, signature:
  unsigned_baseline}` served over cleartext (`mobile_bridge.py:252-290` → `http://127.0.0.1:8101`,
  0.6s timeout); client verifies a checksum string-compare with no signature path
  (`ApkUpdateChecker.kt:34-43`). `POST /mcp/servers` lets anyone overwrite `kelvra-filesystem`
  with `trust_tier=first_party, allowed_tools=[*]` (`api.py:379-390`). In-memory singletons
  (challenges, MCP policy, rate-limit trips) vanish on restart — reboot clears all trips/gates.
- **Fix:** signed manifests only (no unsigned fallback); admin-gated policy writes; persist
  security state or fail-closed on restart.

### A09 Logging & Alerting Failures — High
- **Risk for Kelvra:** allows are silent across the board; blocks are patchy. Never logged:
  dispatch screen failures, worktree-approve secrets blocks (who-tried-to-merge-what),
  `gate/cancel`, MCP registrations, `anomaly/reset`, log reads, webhook 401s (stateless, no
  counter/IP — spoof probes invisible), mobile pair 429/403 (only `print()`). Security events are
  truncated to 140 chars with no actor/IP/user-agent/workspace fields
  (`server.py:63-86,215-243` — and the log itself is world-readable over LAN). Over-logging cuts
  the other way: challenge PINs/tokens, full commands, and FCM tokens land in logs
  (`api.py:294-300`, `security_audit.jsonl:13`; `KelvraWebSocketClient.kt:77,135`;
  `KelvraFirebaseMessagingService.kt:19`).
- **Fix:** log every block/401/secrets-hit with actor, IP, workspace/session, payload-hash (never
  raw secret); untruncate security events; protect `/api/events/log` + `/api/security/*`; stop
  logging PINs/tokens/frames; add tamper-evidence (hash chain) + rotation (unbounded JSONL today).

### A10 Mishandling of Exceptional Conditions — Medium
- **Risk for Kelvra:** a codebase built to handle failure gracefully still leaks on error paths:
  proxy 502s reflect upstream `httpx` errors verbatim (`server.py:2608-2610,2650-2652,2701-2703`,
  host:port included); layout saves return raw `OSError` text (`:792-793`); browser 404s leak
  internal key repr (`:2136-2188`); Telegram webhook's missing `process_mock_update` throws an
  unauthenticated 500 (`router.py:147-155` vs `bot.py:54`); `GET /api/settings/diagnostics`
  exposes platform/cwd/detected-CLIs to anyone (`:1926-1928`); interruption-system race
  short-circuits are correct behavior but their failure branches were never checked for what they
  echo to UI/voice/messaging.
- **Fix:** generic error IDs to callers + server-side correlation IDs; audit every `except`
  branch for what reaches UI/voice/messaging (stack traces, paths, endpoint names); fix the
  Telegram handler name mismatch.

---

## 2. API surface per OWASP API Top 10 (2023)

Bench's UI and Mobile app are both just clients of Bench's local API, so this section governs both.

- **API1 BOLA — Critical:** no object-level authorization anywhere (see A01). Session-, workspace-,
  chat-, agent-scoped reads/writes are interchangeable by ID swap. Fix with ownership checks (§A01).
- **API2 Broken Authentication — High:** no authentication on any Bench or Security endpoint
  except the mobile WS `?token=` check — which the rest of `server.py` bypasses (see A07).
- **API3 Broken Object Property Level Auth — High:** mass-assignment surface is wide open:
  `PATCH /api/workspace/layout` takes arbitrary JSON into `data/layout.json` (`server.py:783-790`);
  `PATCH /api/context` writes arbitrary keys into global standing context (`:972-988`);
  `PATCH /api/workspaces/{id}` + workspace CRUD with no ownership (`:799-824`); MCP register
  accepts `trust_tier`/`read_only` from the caller (see A08). Allowlist writable properties per
  endpoint.
- **API4 Unrestricted Resource Consumption — Medium:** no HTTP-level rate limiting on `:8099` or
  `:8100` (business-logic limiter only); 4-digit gate PINs are brute-forceable (10k space, no
  throttle); Ktor client sets 10MB max frames with no timeout; `upload_skill` has no size cap;
  unbounded JSONL logs. Add velocity limits, PIN entropy + lockout, size caps.
- **API5 Broken Function Level Auth — Critical:** admin-grade functions (worktree approve/reject,
  `run-everything`, follow-up injection into agent logs, MCP policy write, anomaly reset, gate
  confirm) share the same zero-auth plane as reads. Same fix as API1/A01 plus role separation for
  destructive functions.
- **API6 Sensitive Business Flows — High:** pairing (`/api/mobile/pair`), gate confirm, worktree
  approve, and chat confirmations lack anti-automation (no proof-of-presence beyond a text `yes`).
  Require step-up (biometric/step-up token) for pairing-complete, gate-confirm, and merge-approve.
- **API7 SSRF — High:** browser navigate (no private-range/metadata block), MCP server URLs
  (arbitrary, incl. `localhost`/`npx` stdio), Gemini key-in-URL, update manifest over cleartext
  localhost. URL allowlist + egress policy (see A02/A05).
- **API8 Security Misconfiguration — High:** see A02 (CORS `*`, `0.0.0.0`, undocumented endpoints,
  debug defaults).
- **API9 Improper Inventory Management — Medium:** 13 of 16 Security endpoints undocumented;
  `/api/integrations/status` leaks allowlists + webhook topology; debug/legacy paths
  (`unsigned_baseline`, mock pubkeys, `000…` checksums) reachable in non-debug builds. Maintain a
  generated route inventory in CI and fail on undocumented endpoints; strip mock fallbacks behind
  an explicit `KELVRA_ALLOW_MOCKS` flag, never default-on.
- **API10 Unsafe Consumption of APIs — Medium:** Bench consumes OpenAI/Anthropic/Gemini,
  `127.0.0.1:8101`, OSV-style feeds, and webhook payloads with no response validation noted;
  `voice_engine` silently substitutes a simulated transcript on STT failure (`voice_engine.py:68-77`
  — integrity risk, not just availability). Validate + pin upstream response shapes; fail loudly
  instead of simulating.

---

## 3. Mobile per OWASP MASVS (v2)

Honest posture first: much of the below is **not yet implemented** — crypto/pairing are mocks,
protections live in docs/roadmap copy. Each item cites its MASVS requirement ID for traceability.

- **Storage (`MASVS-STORAGE-1/2`) — High:** the bearer `tok-*` session token lives only in a
  `MutableStateFlow` (`DeviceIdentityManager.kt:7-50`); offline cache is in-RAM only
  (`PersistenceModule.kt:31-61`). `androidx.security:security-crypto` is declared but **unused**
  (zero usages in `shared/src`); no EncryptedSharedPreferences/MasterKey/DataStore/Keychain path
  exists. `allowBackup=false` is set (good). **Fix:** persist tokens only via KMP
  expect/actual → Android Keystore / iOS Keychain; never SharedPreferences/UserDefaults/plaintext.
- **Cryptography (`MASVS-CRYPTO-1`) — High:** no real crypto in code — device pubkey is the literal
  string `ed25519-mock-pubkey-…` with a hardcoded timestamp (`DeviceIdentityManager.kt:23,31,58`);
  zero hits for ECDH/HKDF/AES/HMAC/SPKI in `shared/src`. Ed25519-handshake copy exists only in
  roadmap/marketing text. **Fix:** verify against implementation before claiming; implement
  X25519+HKDF session keys with AES-GCM, current non-deprecated algorithms only.
- **Authentication (`MASVS-AUTH-1/2`) — High:** pairing IS the auth mechanism — audit it, don't
  trust "QR worked" (§4). Step-up exists in design (high-risk approvals force open-app biometric,
  `BIOMETRIC_STRONG|DEVICE_CREDENTIAL`) but the receiver that should complete the loop only logs
  and dismisses (`NotificationActionReceiver.kt:18-35`, "Phase 2" TODO — no WS/API call). **Fix:**
  wire approval actions end-to-end with biometric attestation forwarded to Bench (see §4.3).
- **Network (`MASVS-NETWORK-1/2`) — High:** no pinning, no TLS-version config, debug cleartext
  `http://10.0.0.2:8099`, release URL a non-routable placeholder; `debug-overrides` trusts user
  CAs (debug MITM); Ktor has no timeout/pinner (see §4.6 for the TLS floor + pin-set rule).
- **Platform interaction (`MASVS-PLATFORM-1/2/3`) — Medium:** permission set is broad —
  `RECORD_AUDIO`, `WAKE_LOCK`, `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`, foreground mic service
  (`AndroidManifest.xml:5-23,48-51`) — each needs a necessity + narrow-scoping pass; QR-scan
  onboarding copy implies a camera the manifest/Info.plist never declares (add `CAMERA` /
  `NSCameraUsageDescription` or drop the copy); no `FLAG_SECURE`, no biometric face-ID usage
  string gaps to close.
- **Code quality (`MASVS-CODE-1/2/4`) — Medium:** `KelvraLogger`→Napier has no release gate
  (`ENABLE_VERBOSE_LOGS` defined, never read); tokens/frames/FCM tokens logged in release-capable
  paths; ProGuard keeps attributes with no log-strip; hardcoded placeholders (`000…`, mock
  pubkeys, fixed timestamps) must die before prod. No hardcoded real secrets found (good).
- **Resilience (`MASVS-RESILIENCE-1`) — Medium, honestly "no hardening yet":** no
  root/jailbreak/Frida detection in code (docs-only), APK checksum is string-compare with no
  signature verification, Bench's `integrity/verify` is a stub-always-true. Document this posture
  as-is; roadmap (Play Integrity server-checked per `ROADMAP_v2.md`) is the path, not the state.
- **Cadence:** automated MASVS checks every CI build; full manual assessment quarterly or per major
  release (§6 front matter governs).

---

## 4. Connection security — Mobile ↔ Bench (paired self-hosted devices)

Mobile talks to **the user's own Bench instance**, paired via QR + a custom `MobileBridge`
WebSocket protocol (`AgentEnvelope{v,seq,type,ts,payload}`). The standards above don't fully cover
this shape — this section does, concretely.

### 4.1 Pairing flow (`GET /api/mobile/pair/qr` → `POST /api/mobile/pair`) — High
- **As built** (`mobile_bridge.py:78-99,172-210`): 90s nonce expiry with pruning, single-use via
  dict `pop`. **Gaps:** no nonce→IP binding (harvested QR usable from any device on the LAN);
  `GET /pair/qr` itself is unauthenticated + unlimited (fresh-QR harvesting); `Host`-header-derived
  `ws://` URL is attacker-influenceable; restart wipes nonces (replay window resets); client treats
  missing `createdAt` as never-expires (`PairingPayload.kt:7-18`); a screenshotted QR is valid
  anywhere on the network until its 90s lapse — and there is no revocation list for shown QRs.
- **Fix:** bind nonce to requester IP + single展示 session; rate-limit QR issuance; hard-fail on
  missing timestamps client-side; QR payload over an already-authenticated channel where possible.

### 4.2 WebSocket session (envelope sequence) — High
- **As built:** outbound `seq++` + last-1000 buffer + `replay_request` serve
  (`mobile_bridge.py:151-166,323-333`). **Gaps:** Bench never validates inbound client `seq`
  (no continuity, no duplicate suppression, no `from_seq` bounds); no HMAC/signature on envelopes;
  client still routes stale/dup `seq<=last` frames (`KelvraWebSocketClient.kt:88-139`);
  `requestReplay()` only logs; reconnect has no resumption handshake (backoff engine exists,
  unwired — `ReconnectionEngine.kt:14-44`).
- **Fix:** per-client `last_seen_seq` with strict continuity + signed envelopes (session key from
  §4.1 pairing); authenticated resumption that cannot resubmit processed commands.

### 4.3 Voice barge-in channel (`abort_speech` / `cancel_active_speech`) — High
- **As built:** one-time `is_token_authorized(token)` at WS accept, then any frame trusted
  (`mobile_bridge.py:292-347`); `abort_speech` globally cancels Talkback speech with no
  session/device binding, no re-auth, no rate limit; `permission_resolved` only `print()`s — no
  state change, no biometric-proof check. **A voice-interrupt is a command** and gets the same
  bar: per-message auth + device binding + rate limit, with approvals carrying forwarded
  biometric attestation (§3 AUTH).

### 4.4 Endpoints around the pairing — Medium
- `GET /devices` (enumerates ids/names/platforms/online), `POST /devices/{id}/revoke`,
  `POST /integrity/verify`, `GET /latest-version` are all unauthenticated
  (`mobile_bridge.py:212-290`); revocation closes the socket but **keeps the token in
  `paired_devices.json`** (plaintext on disk, linear-scan lookup, no expiry/rotation,
  `:122-135`). Fix: token-auth + ownership on all four; rotate on revoke; encrypt at rest.

### 4.5 Trust model — OPEN DECISION (do not build on an assumption)
- **Undecided:** same-LAN-only vs remote (relay/tunnel) reachability for Mobile→Bench. This
  determines whether public-internet assumptions (public-CA TLS + the 2026 pinning debate) apply,
  or whether paired-device mutual TLS / pairing-established PSK fits better. **The report records
  no answer.** Once decided, document it here with rationale; implementation follows the decision,
  never precedes it.

### 4.6 TLS floor + pinning rule (applies once transport is TLS)
- **Minimum:** TLS 1.3 where the platform supports it, TLS 1.2 floor — pinned in config, never
  left to client defaults. **Pinning:** never a single hardcoded pin (rotation would brick every
  user until an app release). Resilient pin set: current + ≥1 backup for planned rotation.

---

## 5. Messaging integrations (Telegram / WhatsApp / Slack)

Shared intent layer for all channels is the right architecture — keep it. Each channel's credential
+ webhook surface needs its own line (all evidence `kelvra-bench/integrations/`):

- **Credential storage — Medium:** bot tokens/API secrets live in bare env vars
  (`TELEGRAM_BOT_TOKEN`, `WHATSAPP_*`, `SLACK_*` — `*/config.py`), never in `CredentialVault`;
  `.env.example` doesn't document them (shell-history/docker-env sprawl). **Fix:** same
  keyring-based store as provider keys; no second secrets path.
- **Webhook authenticity — High:** WhatsApp HMAC-SHA256 + Slack `v0`+5-min-window checks are
  correctly implemented **but skipped entirely when the secret is unset**
  (`webhook.py:54-61`, `bot.py:63-72`) — and the bot still dispatches in that mode. Telegram has
  **no** `X-Telegram-Bot-Api-Secret-Token` check at all (`router.py:147-155`). **Fix:**
  fail-closed (reject when secret empty); add the Telegram secret-token check.
- **Allowlist + confirmation downgrade — High:** `GET /api/integrations/status` leaks full
  allowlists + webhook topology unauthenticated (`router.py:37-73`); defaults are placeholders
  (`{"arun"}`, `{"1234567890"}`) with a `*` wildcard escape hatch; chat `confirm`/`yes` text
  resolves pending actions without touching the `security_client` challenge
  (`intent_router.py:238-268`). **Fix:** hide allowlists; require explicit non-placeholder
  configuration; bind chat confirmations to challenge IDs.
- **WhatsApp window boundary — Medium:** business verification + 24h reply window constrain
  delivery; define behavior at the boundary — expired-window contexts must never be silently
  reused (re-verify intent, drop stale state), documented here once implemented.
- **Observability — Medium:** webhook 401s and intent-router security blocks return responses only
  — no log, no counter, no IP (spoof/brute-force probes invisible). Log per A09.

---

## 6. Standing process (so this report never goes stale)

**Steering rule** (Bench's own feature — reused, no new mechanism), installed as
`rule-security-report-freshness` in `kelvra-bench`:

> If this task touches authentication, storage, network/transport configuration, cryptography, a
> new third-party dependency / MCP connector / plugin / skill, or a new external integration,
> update the relevant section of the security report (`kelvra-security/docs/`) in the same commit,
> and push it.

- "Push it" = the report change rides the **same commit/push** as the triggering code — never a
  "later" follow-up.
- **Cadence** (also in this file's front matter): automated checks every CI build; full manual
  review quarterly or per major release, whichever comes first.
- **Follow-up (proposed, not built this pass):** CI gate that diffs changed files against
  security-sensitive paths (auth, storage, network config, dependency manifests, MCP/skill/plugin
  dirs) and warns/fails when no report change accompanies them — turning the reminder into an
  enforced gate.

---

## 7. Action checklist (this update)

- [x] OWASP Top 10:2025-mapped web section (§1) — Kelvra-specific findings + evidence
- [x] OWASP MASVS-mapped mobile section (§3) — real requirement IDs, honest mock-vs-done posture
- [x] OWASP API Top 10-mapped section (§2) — Bench's own endpoints
- [x] Connection-security section (§4) — trust model left explicitly OPEN (§4.5)
- [x] Messaging-integrations section (§5)
- [x] Steering rule (§6) installed in kelvra-bench workspace config
- [x] Review cadence in front matter (automated per-build, manual quarterly/per-major-release)
- [x] Commit + push with this task (same-task push — via repo push sequences on completion)
