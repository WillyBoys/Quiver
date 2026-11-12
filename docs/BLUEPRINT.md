# Quiver v2 — Blueprint

This is the design reference for Quiver v2. It records what we are building, why, and the decisions already made, so implementation work can refer back to one place. Update it when a decision changes.

---

## 1. Goal and scope

Quiver v2 is an **AI-powered continuous penetration testing platform**. It runs recurring, agent-driven engagements against an authorized scope and reports how the target's attack surface and risk change from run to run.

**In scope for the proof of concept (PoC):**
- Single operator, self-hosted via Docker Compose.
- **External** track only (internet-facing attack surface).
- Claude as the only LLM, reached through the `bridge` service with either a Claude Code OAuth token or an Anthropic API key (both supported from the start).
- A dashboard to watch runs, approve risky actions, steer agents, and triage findings.

**Designed for, but not built in the PoC:**
- **Internal** and **Web App** tracks (see §9).
- Remote workers running inside client networks.
- Multi-user login and central hosting.
- Other LLM providers.

**Explicitly out:**
- A manual tool hub. Quiver is AI-operated; the human sets up, approves, steers, and reviews.
- Shannon and Ollama (both used in v1).

**Guiding principle: the operator has the final say.** The platform denies what is definitely wrong, asks the operator about anything uncertain, and acts on its own only when an action is definitely safe. When in doubt, it asks. Scope grows only through a deliberate operator change on the settings page (§4.1).

## 2. Lessons from v1

v1 grew from a tool hub, to an agent on the hub, to a multi-agent pipeline on the agent. Its limits all trace back to that layering:

| v1 limitation | v2 response |
|---|---|
| Findings and loot stored as JSON blobs on the session row, with per-session locks to stop overwrites | Typed entity graph with stable identity keys (§5) |
| Agents chose actions by emitting JSON that was regex-parsed from plain text | Native tool calling via the Claude Agent SDK, with tools served from the backend (§7) |
| Pipeline specialists were `Campaign` rows with roles parsed from names | First-class `AgentRun` records with phase, parent, and budget |
| Runs, agents, scheduler, and output buffers lived in one API process's memory | Durable job queue plus a separate worker process (§6) |
| Scope and approval checks spread across several code paths; scope checked only the `target` field | One policy gate in front of all execution, checking the final command (§4) |
| Fuzzy title matching to dedupe findings | Deterministic identity keys; the LLM never decides identity (§5.3) |

Worth carrying forward from v1 as *content*: tool definitions in `backend/app/db/seed.py`; role prompts and phase configs in `agent/pipeline_config.py` (`agent/roles.py` is only a lookup registry); the process timeout and output-cap handling in `execution.py`; the compare-and-swap approval state machine in `api/routes/approvals.py`; the deterministic phase-gate idea; and the P5 tuning lessons (e.g. `secret-hunt` looping on `cloud_enum` until given an explicit stop condition and a tighter budget).

## 3. Architecture

```
                         ┌────────────────────────┐
                         │   Dashboard (React)    │
                         └───────────┬────────────┘
                          REST + live event stream (SSE/WebSocket)
                         ┌───────────▼────────────┐
                         │        API (FastAPI)   │
                         │ engagements · findings │
                         │ approvals · events     │
                         └───────────┬────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │           PostgreSQL            │
                    │ entity graph · jobs · events    │
                    │ approvals · agent sessions      │
                    └───┬───────────────────────▲─────┘
                        │ claims jobs            │ writes results
                ┌───────▼────────────────────────┴───────┐
                │              Worker (Python)           │
                │ orchestrator (phase state machine)     │
                │ scheduler · POLICY GATE · tool runner  │
                │ output parsers · MCP tool server       │
                └───────┬───────────────────────▲────────┘
          starts agent  │                       │ tool calls (MCP)
          sessions      │                       │
                ┌───────▼───────────────────────┴────────┐
                │   bridge (Python, Claude Agent SDK)    │
                │ built-in tools disabled; only Quiver's │
                │ MCP tools are exposed to the agent     │
                └────────────────────────────────────────┘
```

**Containers:** `api`, `worker`, `executor`, `db` (Postgres), `bridge`, `frontend`. An optional `lab` compose profile adds vulnerable targets (e.g. Juice Shop) for end-to-end testing.

The **executor** is the only container that starts tool processes. It holds the tools and nothing else: no secrets, no database access, and no network route to the database. The worker hands it allowed jobs through files (§6), so a tool, even an approved free-form `run_command` or a compromised binary, cannot read Quiver's credentials or reach its database.

**Key rule:** only the executor starts processes, and only for jobs whose spec the worker wrote after the policy gate allowed them. The executor cannot create specs (it mounts them read-only). The bridge, API, worker, and agents cannot execute anything directly.

## 4. Policy gate

Every action request goes through one function before execution:

```
evaluate(action_request, engagement) -> ALLOW | DENY(reason) | NEEDS_APPROVAL(reason) | DEFER(until, reason)
```

An `ActionRequest` carries: tool name, structured parameters, requester (agent run ID or schedule), and the **final argv** that would run. Which parameters are targets, and the tool's risk tier, come from the tool's registry entry (`ToolSpec`), never from the requester.

`evaluate()` (`quiver.core.policy.gate`) is a pure function of the request and a `GateContext` snapshot loaded from the database (`quiver.core.policy.store`). It runs every check and records each one; the final verdict is the most severe: **DENY > NEEDS_APPROVAL > DEFER > ALLOW**. Approval outranks DEFER so the operator can approve while the action waits for its window; the approved action is gated again before it runs, and approval satisfies only NEEDS_APPROVAL checks, never DENY or DEFER.

Decision rule:
- **DENY** what is definitely wrong: anything outside the settings-page scope, an engaged kill switch, an unknown tool. The operator cannot approve a DENY. The only way past it is to change the scope or settings, which is a separate, logged action.
- **NEEDS_APPROVAL** for in-scope actions that are risky or uncertain: the risk tier requires it, targets cannot be extracted with confidence, a pinned resolution has changed, and so on.
- **ALLOW** only what is definitely safe.
- **DEFER** for actions that are allowed but not right now (testing window, rate limits). The job is queued, not dropped.

Checks:
1. **Kill switch:** the global (organization-wide) or engagement kill switch is engaged → DENY.
2. **Engagement and authorization:** engagement in `draft` or `archived`, or no authorization record whose period covers today → DENY. A `paused` engagement → DEFER (no end time), for every tier.
3. **Tool known and enabled:** unregistered or disabled tools → DENY. (v1 treated unknown tools as passive.) A tool's tier may depend on its parameters (e.g. nuclei exploit templates), but only upward; if that classification fails, the tier is treated as `arbitrary` and the action needs approval.
4. **Scope** (§4.1):
   - Typed tools **declare which parameters are targets**, and those are checked directly.
   - A passive tool's **domain-subtree** parameter (subdomain enumeration, certificate transparency) stands for the names below a domain rather than the domain itself (§4.1). The same name in its argv gets the same decision; nothing else does. The rule applies only while the tool's tier is passive.
   - **Standard input** (a tool's target list, built from its typed parameters) is checked like argv, except that every name in it is a definite target: out of scope is DENY, not approval. A line starting with `-` needs approval. `run_command` never gets standard input.
   - Every target that can be extracted from the final argv is also checked, as defense in depth (`quiver.core.policy.argv`). For `run_command` this is the only check. URLs, IPs, and CIDRs are definite targets. Dotted names whose last label is a real top-level domain are *possible* hosts, since they may be file names (`out.sh`); out of scope, they need approval rather than denial and create no suggestion. Tokens that might be addresses in a non-standard form (`1.5`, `0x7f.1`), zone IDs, and non-ASCII names → NEEDS_APPROVAL. Flags, bare integers, and absolute or `./` paths are skipped, so typed tools pass numbers as integers.
   - Excluded target → DENY. Out-of-scope target → DENY, and a `ScopeSuggestion` is created (for a URL, its host) unless the target could never be an include entry (loopback, public suffix).
   - Exception: a **passive** tool may act on an out-of-scope target that has a **pending** suggestion (§4.1, passive lookups). Excluded targets stay denied.
   - Uncertain targets, or no identifiable target for a non-passive tool → NEEDS_APPROVAL. Scope that cannot be loaded (a corrupted entry) → DENY.
   - For `run_command`, a URL with an excluded path below it → NEEDS_APPROVAL, since a free-form command may crawl.
   - **Resolution** (non-passive tiers): every in-scope hostname, including the host of a URL target, is resolved before evaluation, and each answer must lead somewhere testable. A failed or partial answer → NEEDS_APPROVAL. Any address that is loopback, link-local (including cloud metadata), multicast, reserved, or unspecified → DENY. An excluded address → DENY. A private or otherwise non-public address that no include entry covers → DENY. A name matched only by a wildcard whose uncovered addresses or CNAME chain belong to a known third-party provider → DENY, and the exact hostname is suggested. Then pinning: the first acceptable answer is pinned; later answers within the pin pass, and new addresses → NEEDS_APPROVAL. More than 20 names in one action are not resolved, and the action needs approval.
5. **Testing window:** outside the engagement's windows → DEFER until the next opening; no windows → DEFER with no end time. **Passive tools are exempt**: they contact third parties, never the asset.
6. **Rate, concurrency, and usage budgets** → DEFER for 15 seconds, then gated again. Per engagement: jobs running at once (default 3), jobs started per minute (default 30); per target host or network: jobs running at once (default 1). Engagements can override each limit (1–1000). They count real jobs (dispatched or running), from a snapshot the worker passes in. The model-usage budget joins this check with agent budgets (step 16).
7. **Risk tier vs engagement autonomy** → ALLOW, NEEDS_APPROVAL, or DENY when the tier is `off`.

Every decision is written to the event log as a `policy.decision` event: tool, argv, parameters, requester, verdict, every check with its reason, every target with the scope entry that decided it, and every DNS answer used.

`evaluate()` never touches the network. The store computes `hostnames_to_resolve()`, resolves them through an injectable `Resolver` (`quiver.core.policy.resolve`; dnspython in the worker, a static table in tests), and passes the answers and the stored pins into the context. The API never resolves names.

**Re-evaluation at execution:** an approved or deferred action goes through the gate again immediately before it runs. Scope, window, or kill switch may have changed while it waited. Approvals expire after a configurable period (`approval_ttl_hours`, default 24) if the job has not started, and an expired approval must be requested again.

**An approval covers exactly the reasons the operator saw.** When the gate re-evaluates an approved job, it passes only if every reason it now asks approval for was among the approved reasons (`apply_approval`). A new reason, such as another target or a hostname that now resolves somewhere new, creates a new approval request. Approval never overrides DENY or DEFER.

**Running jobs:** an engaged kill switch (global or engagement) or an archived engagement cancels every job that has not finished; running ones are stopped through the executor. After any scope change, running jobs gated before it are gated again, and cancelled if they are now denied.

### 4.1 Scope semantics

**The settings page is the only source of scope.** Agents and scanners can discover assets and *suggest* them, but cannot act on them. The operator approves a suggestion by adding it to scope, a deliberate choice that is recorded. Everything else is denied by default.

- **Entry types:** IP, CIDR (IPv4 and IPv6), exact hostname, wildcard (`*.client.com`), and URL. Each is either an include or an exclude, and excludes always win.
- **Entries are validated and normalized when entered** (`quiver.core.scope`), never silently corrected. The kind is detected from the value; hostnames are lowercased and converted to punycode (UTS #46 + IDNA 2008), so Unicode lookalikes stay distinct from the real domain. An include entry is rejected if it:
  - is or overlaps loopback, link-local (including cloud metadata at `169.254.169.254`), multicast, broadcast, unspecified, or IPv4-mapped IPv6 addresses;
  - is wider than IPv4 /8 or IPv6 /32;
  - is a single-label name, or a hostname or wildcard on a public suffix (`co.uk`, `*.com`, `*.github.io`);
  - is a CIDR with host bits set (`10.0.0.5/24`; the operator must enter the network address);
  - is a URL with credentials, a query or fragment, or `.`/`..` path segments.

  Excludes only need to be well-formed, because a broad exclude can only narrow scope.
- **An apex does not imply its subdomains.** `client.com` covers only `client.com`. Subdomains require `*.client.com` or their own entries.
- **Matching** (`quiver.core.scope_match.Scope.check`) returns `in_scope`, `out_of_scope`, `excluded`, or `uncertain`, plus the entry that decided it. Every ambiguity resolves toward less testing:
  - Exclusions always win, and any overlap counts: a CIDR sweep or crawl that would touch an excluded address or path is excluded as a whole.
  - Includes match strictly; exclusions match loosely. An excluded hostname also excludes its subdomains. Excluded URL paths match case-insensitively, ignore `;params` and repeated slashes, and apply to every scheme and port on that host.
  - A wildcard covers names at **any depth** below its base, never the base itself. An exact hostname covers only itself.
  - A URL entry covers **only web requests** with the same scheme, host, and port, under its path prefix at a segment boundary. It does not put the host in scope for host-level actions such as port or TLS scans. A host in scope covers every URL on it, on any port.
  - A CIDR target must be covered entirely by include entries (adjacent entries combine).
  - Dot segments and encoded unreserved characters are resolved before matching (`/portal/../admin` is `/admin`). Targets that cannot be read with confidence are `uncertain` and go to the operator: IP addresses in non-standard forms (`2130706433`, `0x7f.1`), credentials in URLs, encoded separators or double encoding, backslashes, non-HTTP schemes, and IPv6 zone IDs. IPv4-mapped IPv6 addresses are matched as IPv4.
  - Host-level actions on a host whose web root (`/`) is excluded are `uncertain`.
  - Matching is name-based. An IP entry never puts a hostname in scope by itself; resolution is checked by the gate.
  - **Domain subtree** (`check(domain, domain_subtree=True)`, passive tools only): the names below a domain are in scope when the domain itself is in scope (exactly or through a wildcard) or when `*.<domain>` is an include. So `*.client.com` allows asking third parties which names exist under `client.com`, while `client.com` itself stays out of scope for anything that touches it. Excluded when the domain is excluded (including by a hostname exclude above it) or when `*.<domain>` is an exclude. An exclusion somewhere below the domain does not block the lookup: the lookup reaches only third parties, and names found there are recorded as `excluded` without a suggestion. IPs, URLs, and wildcards as subtree targets are `uncertain`.
- **Wildcards cover names, not infrastructure.** A hostname matched only by a wildcard is in scope for active work only if it resolves to an in-scope IP or CIDR, or to infrastructure that is not a known third-party provider (CDN, cloud hosting, SaaS). Otherwise the gate denies it and suggests the exact hostname. An exact hostname entry is an explicit operator choice and is not subject to this check. An in-scope address wins over provider evidence.
  - Providers are recognized by published address ranges (AWS, GCP, Google, Cloudflare, Fastly, Oracle, GitHub Pages, DigitalOcean) and by CNAME suffixes for those without a stable list (Azure, Akamai, Heroku, Netlify, Vercel, Shopify, and other SaaS hosts). The data is a bundled snapshot, `quiver/core/policy/data/providers.json`, regenerated by `scripts/update_providers.py` and reviewed in a PR like code.
- **Every resolved address is checked, for every hostname** (exact or wildcard): loopback, link-local and metadata, multicast, reserved, and unspecified addresses are always denied, as are excluded addresses. A private or non-public address (RFC 1918, CGNAT, unique-local IPv6, documentation ranges) is denied unless an include entry covers it, so DNS cannot steer the worker into its own or the client's internal network.
- **Resolution pinning:** the first time the gate lets an action reach an in-scope hostname, its addresses are pinned (`HostResolution`). The decision carries the addresses each job may use; where the tool allows, the runner gives it the IP plus a Host header or SNI. If a hostname later resolves to an address outside the pin, the gate returns NEEDS_APPROVAL (or DENY if that address fails the checks above). The operator accepts new addresses on the engagement's resolutions page, which adds them to the pin (so round-robin and CDN rotation stop asking once seen); the acceptance is logged with a reason. Accepting never makes a denied address testable, because the checks run on every evaluation.
- **Passive lookups on suggestions are allowed.** DNS resolution, certificate transparency, WHOIS, and ASN/hosting lookups go to third-party services, not the asset, so they may run against assets with a *pending* suggestion (not dismissed ones, and never excluded ones), at any time of day. That gives the operator evidence to decide with. Nothing that sends traffic to the asset itself runs until the asset is in scope.
- **Redirects and crawling:** typed tools are configured so they never follow a redirect or link to a host outside scope. Out-of-scope redirect and link targets become suggestions.
- **Scope changes:**
  - Additions take effect for jobs gated after the change.
  - Removals take effect immediately and cancel queued jobs that no longer pass the gate.
  - Every change is a `ScopeChange` record (who, when, why, and the suggestion it came from, if any), linked to the engagement's authorization record.

**Default External autonomy** (risk tiers in `quiver.core.policy`):

| Tier | Action class | Default |
|---|---|---|
| `passive` | Passive recon (DNS, certificate transparency, OSINT) | Auto, any time |
| `discovery` | In-scope discovery scans (port scan, HTTP probe, fingerprinting) | Auto, within window |
| `intrusive` | Vulnerability validation / attack payloads (nuclei exploit templates, sqlmap-style, credential attempts) | Approval |
| `arbitrary` | `run_command` (free-form escape hatch) | Always approval |

Engagements can override each tier with `auto`, `approval`, or `off` (DENY), except that `arbitrary` can never be `auto`. Every decision is written to the event log.

## 5. Data model

### 5.1 Engagement layer
- `Engagement`: name, track(s), status, autonomy overrides per tier, kill switch (time engaged and reason), schedule, usage budget, notification settings. The global kill switch lives on the organization. Engaging or releasing either is logged as an event with the operator who did it.
- `ScopeEntry`: IP / CIDR / hostname / wildcard / URL, with an `include` or `exclude` flag.
- `HostResolution`: per engagement and in-scope hostname, the pinned addresses, the latest answer (addresses, CNAME chain, error), the third-party provider if known, and when the operator last accepted new addresses (§4.1).
- `ScopeSuggestion`: an asset found outside scope, one per engagement and normalized value. Holds how it was found (source, evidence from the first sighting), first and last seen, sighting count, the addresses and hosting provider from a passive lookup on each sighting (ASN details later), and status: `pending`, `added`, `dismissed`, or `excluded`. Repeat sightings never reopen a decided suggestion. *Add* creates an include entry (the operator may enter a different value, such as a covering wildcard), *exclude* creates an exclude entry so the asset is not suggested again; both go through the normal scope path with a reason, and the `ScopeChange` links the suggestion. A dismissed suggestion can still be added or excluded later. Only pending suggestions allow passive lookups (§4).
- `ScopeChange`: append-only audit of every scope edit: who, when, why, and the linked suggestion if any.
- `TestingWindow`: allowed ISO weekdays (1 = Monday), start and end time, IANA timezone. An end before the start crosses midnight; equal start and end means the whole day. **No windows means no active testing**: the gate defers everything except passive lookups until a window exists.
- **Activation:** an engagement moves from `draft` to `active` only when it has an authorization record whose period covers today, at least one include scope entry, and at least one testing window. Statuses: `draft → active ⇄ paused`, any → `archived`, which is final and read-only.
- `Authorization`: who authorized testing (name, title, organization, contact), the date, and an optional validity period. Uploading the signed document is planned; until then, reference it in the notes.

### 5.2 Execution layer
- `Run`: one execution of an engagement (scheduled, triggered, or on demand): status, start and end, and a summary of what changed (budget usage is added in step 16). Jobs may belong to a run; entities, relationships, and findings record the runs they were first and last seen in.
- `AgentRun`: one agent session within a run. Has phase, role, parent, status, budget, and the bridge session ID for resume.
- `Job`: one tool execution. Tool, structured parameters, the argv built from them (fixed at submission, so what is approved is what runs), requester, status, the latest gate or executor reason, the targets and pinned addresses from the last gate decision, **worker label** (`local` for now), timings, exit code, and output size. Raw output stays on disk (§6). Statuses: `submitted` → `queued` | `deferred` | `awaiting_approval` | `denied`; `queued` → `dispatched` → `running` → `succeeded` | `failed` | `timed_out` | `lost`; anything unfinished → `cancelled`.
- `ApprovalRequest`: the job (the exact argv and targets), the reasons the gate asked approval for, status (`pending`, `approved`, `denied`, `expired`), the decision with operator note, and an expiry once approved. The agent's reasoning is added in step 15. One pending request per job at a time.
- `Event`: append-only log of everything (policy decisions, kill switch changes, job status changes, agent messages, graph changes, scope changes). Each has an organization, an optional engagement (none for global events), an optional acting user, a `kind` such as `policy.decision`, a JSON payload, and a strictly increasing `seq` (the log's order, and the cursor for the live stream). Drives the dashboard and the audit trail. Job output itself stays on disk (§6); events only reference it.

### 5.3 Knowledge graph
Typed entities with relationships. Every entity has a **deterministic identity key**, first and last seen (time and run), a scope status, and a `status`.

| Entity | Identity key (`quiver.core.graph.keys`) |
|---|---|
| `host` | `host:<ip>`: IPv4-mapped IPv6 becomes IPv4, IPv6 compressed lowercase (hostnames attach as `domain` → `resolves_to` → `host`) |
| `domain` | `domain:<fqdn>`: lowercase, no trailing dot, punycode (UTS 46 + IDNA 2008), so lookalikes stay distinct |
| `service` | `service:<ip>:<port>/<tcp\|udp>` |
| `certificate` | `certificate:<sha256>`: 64 lowercase hex digits |
| `web_endpoint` | `web_endpoint:<scheme>://<host>:<port><path>`: default port explicit; credentials, query, and fragment dropped; unreserved escapes decoded, other escapes uppercased, dot segments removed |
| finding | `finding:<issue type>\|<entity key>\|<location>` |

Two sightings are the same entity exactly when their keys match. Keys are computed only by these functions, never by an agent; invalid input is rejected, not guessed. Relationships (External): `domain resolves_to host`, `host exposes service`, `service presents certificate`, `certificate names domain`, `service serves web_endpoint`, `web_endpoint on_domain domain`.

**Storage:** one `entities` table and one `relationships` table. Each entity type is registered in code (`quiver.core.graph.types`): its identity attributes, how attributes are cleaned (strings ≤ 2 KB, ≤ 16 KB per sighting), its key, and what to scope-check. Tracks register their own types and relationships without migrations (§9). Attributes beyond the identity are reported data: target-controlled, kept as data, and never used for decisions. A new sighting updates what it reports and never drops attributes.

**Recording** (`quiver.core.graph.record.record()`) is how parsers and agents write: entities, links, and findings in one call, validated completely before anything is written (one bad item rejects the call). Every sighting writes an `Observation` (source, job, run, time, what was seen), which reconciliation reads (§8). Each entity's **scope status** (`in_scope`, `out_of_scope`, `excluded`, `uncertain`, `not_applicable`) is computed at each sighting from the current scope; out-of-scope discoveries are kept in the graph and create a `ScopeSuggestion` (excluded ones do not). Scope status is information only: the policy gate decides what may be touched. The API exposes the graph read-only.

`Finding`: the issue type, affected entity, location, title, severity, status (§5.4), details, and the scope status of its entity. `Evidence` links a finding to the job(s) and output excerpts (capped at 8 KB, untrusted) that support it.

### 5.4 Finding lifecycle
```
candidate ──validated / operator──▶ confirmed ──same check ran, negative──▶ fixed
    │                                  │  ▲                                    │
    │                                  │  └──────── seen again ────────────────┘ (= regressed)
    │                                  ├──operator──▶ accepted_risk
    │                                  └──entity unreachable──▶ stale ──reachable again──▶ re-checked
    └──operator rejects──▶ false_positive
```
- Agents and scanners create **candidates** only. A candidate stays a candidate until validated or reviewed by the operator. A new sighting of a finding refreshes its title, severity, and details but never changes its status. (Until step 24, candidate is the only status created.)
- **Confirmed** requires validation evidence (a successful reproduction) or operator review.
- **Fixed** requires that the same check ran against the same entity, the entity was reachable, and the result was negative. A finding whose entity could not be reached becomes **stale**, not fixed.
- **Regressed** is a fixed finding that is seen again. It is shown prominently.
- Reports and headline numbers count confirmed findings; candidates are shown separately.

## 6. Execution

- **Queue:** Postgres-backed (`SELECT … FOR UPDATE SKIP LOCKED`); no extra broker needed. Jobs carry a worker label so remote workers can be added later. Jobs are created by `enqueue()` (playbook and agents) or by the operator (`POST /engagements/{id}/jobs`). Either way the request is only recorded: the API never gates or runs anything.
- **Scheduler** (worker, one loop per second): collects executor results; applies cancellations; gates due jobs and writes the spec for allowed ones; marks jobs the executor never started (60 s) or never finished (hard timeout + 60 s) as `lost`.
- **Handoff:** two named volumes (`job_specs`, `job_output`), each writable by one side only. The worker writes `job_specs/<job_id>.json` (argv, timeouts, output cap) and `<job_id>.cancel`; the executor mounts them read-only. The executor writes `job_output/<job_id>/` (`started`, `output.log`, `result.json`); the worker mounts it read-only and treats it as untrusted, because tools run where it is written. Files are written to a temporary name and renamed.
- **Executor:** runs the argv without a shell, in a new session (so the whole process group can be killed), with stdin from `/dev/null` (or the spec's `stdin` text, at most 256 KB, for tools that read a target list; the worker builds it from typed parameters and the gate checks it), the job's output directory as working directory and `HOME`, and an environment that inherits nothing (`PATH`, `LANG` only). Output is read in 64 KB chunks, not lines, and capped (10 MB). Carries over v1's idle (10 min) and hard (45 min) timeouts. Timeouts, the cap, cancellation, and the main process exiting all kill the whole process group. Jobs interrupted by an executor restart are reported `lost`. The image is the tools image: `python:3.12-slim` plus each tool as a release binary pinned by version and per-architecture SHA-256, verified at build time (a mismatch fails the build). Upgrades are reviewed PRs made with `scripts/update_tools.py`, which reads each release's checksums file and rewrites the pins (`--check` validates them offline). Our own stdlib clients (`quiver-ct`) are copied into the image as standalone scripts that run under `python3 -I`. Debian packages (e.g. nmap) come from the Debian release the base image tracks. Kali was considered and rejected: its rolling repository cannot pin versions, and the typed tool set is small. Typed tools are invoked with off-scope redirect following disabled and with pinned addresses where supported (§4.1).
- **Raw output** is stored on disk (`job_output/<job_id>/output.log`) and referenced from the `Job`; it does not go into the database. Live output streams to the dashboard from those files.
- **Live updates:** the worker writes events to Postgres and signals with `LISTEN/NOTIFY`; the API relays them to the dashboard over SSE.
- **Parsers:** each typed tool has a parser that turns output into graph changes (e.g. nmap XML → `Host`/`Service`). Parsers are pure functions `(output bytes, job params) → entities, links, findings`, tested with recorded fixtures (`tests/fixtures/tools/<tool>/`). Output is untrusted: lines a parser cannot use are counted as skipped, every item is validated against the graph types first (so one bad line never makes `record()` reject the job), results are limited to what the job asked about (names below the queried domain, hosts on the input list), and at most 50,000 entities are taken per job.
- **Parse stage:** when a job with a parser succeeds, its `parse_status` becomes `pending`. A parse loop beside the scheduler tick (so a large result never delays gating) takes one job per transaction: it reads `output.log` without following symlinks (the job directory and file are opened with `O_NOFOLLOW` relative to the output root and must be a regular file, because any job could plant a link to a file in the worker, such as a secret), runs the parser, and records the result with `source="parser:<tool>"`, the job, and its run, in batches inside a savepoint. Success emits `job.parsed` with counts, skipped lines, and the tool's own notes (e.g. subfinder source errors, since it exits 0 when every source failed). Any failure rolls back that job's graph writes, sets `parse_status=failed` with the error, and emits `job.parse_failed`; the job itself stays `succeeded`.
- **Restart safety:** jobs, agent runs, and approvals live in the database. After a restart the worker picks up unfinished work, and agent sessions resume through the bridge.

## 7. Agents

### 7.1 Runtime: bridge
The bridge moves from "prompt in, text out" (`claude --print`) to an **agent runtime** built on the Python Claude Agent SDK. It is code in `src/quiver/bridge/` that shares `core` schemas, but it runs in its **own container** with its own image, so the Claude credential never sits in the worker that processes target output:
- Built-in tools (Bash, file editing, web access) are **disabled**.
- The agent's only tools are Quiver's, served by the worker as an **MCP server**.
- The bridge streams agent events (messages, tool calls, thinking summaries) back to the worker, which writes them to the event log.
- Sessions can be resumed, so an agent can continue after an approval that takes hours.
- **Approvals never block a tool call.** An approval-gated or deferred tool returns at once with `queued: <approval or job id>`. The agent continues with other work or ends its turn. When the operator decides (or the deferred job runs), the worker resumes the session with the result as a new message.
- The runtime must not load host or user Claude settings, memory files, or plugins. Its configuration comes only from Quiver.

**Authentication modes:** the bridge accepts either `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`. Both paths are built and tested from the start; unattended scheduled runs should prefer the API key. The worker talks to an `AgentRuntime` interface, so a direct Anthropic SDK implementation can be added later without touching the orchestrator.

> Hosting Quiver for other users would change the authentication story. Subscription OAuth is for the PoC only; review Anthropic's terms before any hosted deployment.

### 7.2 Orchestration
- Each run starts with the track's **baseline playbook** (§8), which is deterministic. Agents then add depth on top of it.
- A **code state machine** (not an LLM) owns phases and gate conditions. Gates are queries against the graph (e.g. "≥1 live HTTP service found").
- External phases: **recon → discovery → validation**, then **reporting** (a summary of changes since the last run).
- Each phase runs **one lead agent**. Parallel specialist sub-agents come later, only if single agents prove to be the bottleneck. They also use up subscription limits faster.
- Between phases, a synthesis step turns graph changes into concrete directives for the next phase (carried over from v1, now reading the graph instead of text summaries).

### 7.3 Agent tools (External, initial set)
| Tool | Purpose |
|---|---|
| `query_assets`, `query_findings` | Read the graph (filtered, paginated) |
| `record_observation` | Add or update graph entities with a source job |
| `record_finding` | Create a **candidate** finding with evidence |
| `subdomain_enum`, `dns_resolve`, `cert_transparency` | Passive recon |
| `port_scan`, `http_probe`, `tech_fingerprint`, `tls_scan` | Discovery |
| `nuclei_scan`, `content_discovery` | Vulnerability discovery |
| `validate_finding` | Run a targeted reproduction (approval-gated) |
| `run_command` | Escape hatch; always needs approval |
| `request_human` | Ask the operator a question; the agent pauses until answered |

Typed tools take structured parameters; the worker builds the argv. Implemented so far: `subdomain_enum` = subfinder (`domain`, a domain-subtree target; `max_minutes`), `dns_resolve` = dnsx (`hosts`, up to 1,000 names, passed on standard input), `cert_transparency` = `quiver-ct` (`domain`, a domain-subtree target; `max_minutes`). `quiver-ct` is a stdlib crt.sh client: it queries `%.<domain>` and `<domain>` (unexpired certificates), builds the URL itself, refuses redirects (so it contacts only `https://crt.sh/`), retries 429/5xx with backoff, decodes the JSON array incrementally with a 20 MB cap per query, and prints one JSON line per certificate plus a summary (errors, truncation). It exits non-zero only when every query failed, so an outage fails the job instead of reading as "no certificates". crt.sh has no certificate SHA-256, so CT results are `domain` entities, not certificates: each name a certificate covers (`*.x` recorded as `x` with `ct_wildcard`), with `ct_certs`, up to five `ct_issuers`, and the earliest `not_before` / latest `not_after`; e-mail addresses and free text in certificates are skipped. Their argv holds only the target and integers: no resolver addresses or provider URLs, which the gate would check as targets. Tools choose their own sources and public resolvers. Tool results returned to the agent are **summaries plus graph changes**, not raw output dumps; agents fetch detail through query tools when needed.

### 7.4 Agent safety and limits
- Tool output is target-controlled and **untrusted**. It is delimited and labeled as data in tool results. The policy gate, not the model, is what enforces scope.
- Because agent reasoning can be shaped by target content, the approval screen leads with the exact command and targets. The agent's reasoning is shown below them and labeled as untrusted. `request_human` questions are labeled the same way.
- **Budgets per agent run:** maximum turns, wall-clock time, and tool calls. Exceeding a budget ends the agent run gracefully with a summary.
- **Budget per engagement:** a model-usage cap per day and per run, so continuous testing cannot exhaust the account's limits. Reaching it defers further agent work.
- **Usage limits:** when the bridge reports a rate or usage limit, the run **pauses and resumes later**; it does not fail.
- **Refusals:** a model refusal is recorded as an event, shown on the dashboard, and the phase continues or skips. It is never retried in a loop.
- **Model:** set per role in config. Default is the most capable current Claude model for lead agents.

## 8. Continuous testing

- **Baseline playbook:** each track defines a fixed, deterministic sequence of tool runs with no LLM involved. For External: subdomain enumeration, resolution, port scan, HTTP probe, fingerprinting, TLS scan, and nuclei discovery templates. It runs the same way every time, so the run-to-run diff reflects changes in the target, not in what an agent chose to do. Reconciliation of `fixed` depends on this consistent coverage. Agents add depth, chaining, and validation on top of it, and their findings are re-checked in later runs through recorded, repeatable checks.
- **After every run, reconciliation** updates `first_seen`/`last_seen` and applies the finding lifecycle rules (§5.4): `fixed` only when the same check re-ran against a reachable entity, `stale` when unreachable, `regressed` on reappearance.
- **Triggers:**
  - Scheduled lightweight recon (e.g. daily); this runs the baseline playbook only.
  - Change-triggered deeper work (new host, new service, version change, new subdomain).
  - Scheduled full runs (e.g. weekly).
  - On-demand from the dashboard.
- The **run summary** ("what changed") is a first-class record and the main thing the dashboard shows.
- **Notifications:** pending approvals, new scope suggestions, regressions, and runs paused by limits trigger a notification (webhook first, e.g. Slack or email relay), so unattended runs do not stall unnoticed.

## 9. Tracks (future-proofing)

A track is a plug-in module that provides:

| Contribution | External (PoC) | Internal (later) | Web App (later) |
|---|---|---|---|
| Entity types | Host, Domain, Service, Certificate, WebEndpoint | Identity, Credential, AD objects | WebApp, Parameter, AuthSession |
| Tool pack and parsers | recon/discovery tools | netexec, impacket, certipy, bloodhound | Playwright browser, HTTP replay, fuzzers |
| Phases and agent roles | recon → discovery → validation | discovery → credentials → lateral movement | crawl → auth → per-vuln-class specialists |
| Extra policy rules | scope, rate limits | no account lockouts, no destructive AD changes | no state-changing requests without approval |
| Worker placement | `local` | worker **inside the client network** | `local` |

The core must support these from the start, even though only External uses them:
1. Track-registered entity and relationship types.
2. Worker labels on jobs.
3. A platform-owned **credential store**. Agents refer to credentials by ID, never by plaintext value.
   - **Recon API keys** (subfinder's keyed sources, Shodan, and the like) are not used yet: passive tools use keyless sources only, because the executor holds no secrets. When keys are needed, they go to a separate **keyed executor**: a second executor service that mounts only recon key files as Docker secrets (no database, no Claude credentials, no other secrets), runs only an allowlist of typed tools (never `run_command`; enforced by the worker when it picks the executor and again by the keyed executor on `argv[0]`), and is selected by a `ToolSpec` field. Keys never appear in argv, specs, or job output.
4. Tool registry, phases, and roles loaded per track.

## 10. Dashboard

1. **Overview:** what changed since the last run, confirmed-finding counts by severity, the attack surface over time, and the next scheduled run.
2. **Live run:** current phase, active agent and its plan, a timeline of actions with brief reasoning, budget and usage.
3. **Approvals:** pending actions, with the exact command and targets first and the agent's reasoning below, labeled as untrusted (§7.4); approve or deny with a note; send guidance to the agent.
4. **Scope suggestions:** assets found outside scope, each with its evidence (how it was found, what it resolves to, who hosts it). Actions: *add to scope*, *dismiss*, or *exclude*. Adding opens the scope editor pre-filled, so the operator confirms the exact entry and gives a reason.
5. **Findings:** triage list (candidate / confirmed / fixed / stale / regressed / accepted risk), with an evidence chain (finding → evidence → job → command) and attack-path views.
6. **Engagement settings:** scope (the only source of scope), exclusions, scope change history, window, schedule, autonomy, usage budget, notifications, authorization record, kill switch.

Markdown report export from the findings view. DOCX/PDF later.

## 11. Platform security (even for a single user)

- Ports bound to `127.0.0.1` by default; remote access through an SSH tunnel.
- A single-user login with a session token on every API route and the event stream. Passwords are Argon2id; the session token is an HttpOnly, SameSite=Strict cookie, and only its keyed hash (HMAC with the API secret key) is stored. Interactive API docs are off unless enabled for development.
- CORS restricted to the frontend origin.
- No default secrets; generate them on first run or refuse to start.
- No Docker socket mounted into any container.
- Tool processes run only in the `executor` container: no secrets, no Quiver dependencies (only its stdlib-only code), not attached to the backend network (so the database is unreachable by name or address), job specs mounted read-only. It runs as a non-root user with every capability dropped; raw-socket capabilities are added only when a tool needs them (step 11), with a comment.
- `user_id` / `org_id` columns on top-level tables, so multi-user can be added later without a data migration.

## 12. Testing strategy

- **Unit:** policy gate (verdict precedence, kill switches, scope extraction, lookalike domains, IPv6, exclusions, apex-vs-wildcard, third-party resolution, pinning changes, windows, re-evaluation of approved actions), parsers (with recorded fixtures), identity keys, reconciliation logic (including `stale` vs `fixed`).
- **Replay:** run the orchestrator and agents against recorded tool outputs, with no network access. Use this for agent regressions without scanning anything.
- **Lab:** end-to-end runs against the `lab` compose profile.
- Each new tool lands with a parser and at least one fixture.

## 13. Stack

| Layer | Choice |
|---|---|
| API and worker | Python 3.12, FastAPI, SQLAlchemy 2 (async), Alembic migrations; one Python package (`uv`-managed) built into separate API and worker images |
| Live updates | Postgres `LISTEN/NOTIFY` → API → SSE |
| Database | PostgreSQL 16 |
| Agent runtime | Python Claude Agent SDK, in the `bridge` container |
| Tool protocol | MCP (worker hosts the server; bridge connects to it) |
| Frontend | React + Vite |
| Packaging | Docker Compose; executor tools image on `python:3.12-slim` with pinned, checksum-verified tool binaries |

## 14. Proposed repository layout

```
quiver/
├── pyproject.toml        # one Python package for core, api, worker, and bridge
├── src/quiver/
│   ├── core/             # shared models, schemas, identity keys, policy gate
│   ├── api/              # FastAPI app: routes, auth, SSE event stream
│   ├── worker/           # orchestrator, scheduler, runner, MCP server
│   │   └── tracks/
│   │       └── external/ # entity types, tools, parsers, playbook, phases, roles
│   ├── bridge/           # agent runtime (own container; holds the Claude credential)
│   └── migrations/       # Alembic
├── frontend/             # dashboard
├── docker/               # api, worker, executor (tools image), bridge, frontend
├── tests/                # unit, replay fixtures, lab e2e
├── docs/
└── docker-compose.yml
```

The policy gate lives in `core` as pure functions, so it can be tested without the worker.

## 15. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Skeleton | Compose stack boots; API login; database migrations; CI runs tests |
| M1 | Engagement + policy | Engagements, scope, scope suggestions and change log, windows via API; policy gate (incl. §4.1) fully unit-tested |
| M2 | Execution + graph | Worker runs typed External tools; parsers fill the graph; the baseline playbook runs end to end; reconciliation produces a "what changed" diff across two runs |
| M3 | Agents | Bridge agent runtime with MCP tools; phase state machine; non-blocking approvals with resume; budgets; refusal and usage-limit handling |
| M4 | Dashboard | Overview, live run, approvals, scope suggestions, findings, settings, all fed by the event stream |
| M5 | Continuous | Scheduler, change triggers, finding lifecycle (fixed/stale/regressed), notifications, Markdown report |
| M6 | Hardening | Replay test suite, lab profile, kill switch, docs; tag `v2.0` |

## 16. Open questions

- Which nuclei template categories count as "validation" (approval) versus "discovery" (auto)? When unsure, a category goes to approval.
- How long to keep raw job output, and whether to encrypt client data at rest.
- Which third-party provider ranges (CDNs, clouds, SaaS) to ship for the wildcard check in §4.1, and how to keep them updated.

**Resolved:**
- Bridge language: Python Agent SDK, in its own container (§7.1).
- Auth: OAuth token and API key both supported from the start (§7.1). Review Anthropic's terms before relying on the subscription token for unattended runs.
- Reconciliation no longer needs "N consecutive misses". `fixed` requires the same check to re-run against a reachable entity and come back negative, and an unreachable entity becomes `stale` (§5.4).
