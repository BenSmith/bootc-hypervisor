# The credential broker

`libexec/agent-broker` — why this program exists, what it refuses to do, how it
knows which sandbox is calling, and how to run it.

A sandboxed coding agent never receives a provider API key. It calls the
provider's real hostname, exactly as it would with a key; its workload's egress
inspector recognises a policy entry naming a credential and sends that request
to the broker instead of to the origin, and the broker attaches the real
credential on the way out. Inspector → broker is plain HTTP on a loopback
address the guest cannot reach; broker → provider is ordinary verified TLS from
the host, and the agent never holds the credential.

**The guest is told nothing.** It has no endpoint, no variable and no name for
the broker — so it cannot choose to use one, cannot decline to, and cannot be
pointed at another workload's. Earlier revisions of this design did hand the
guest a base URL; §2 and §4 record why that was sound and §7 records why it is
gone. The broker's own path involves no TLS interception and breaks no
certificate pinning. (Since 2026-08-26 a *filtered* VM does carry a CA for a
different reason — its egress inspector terminates TLS by default; see
`adr/008-transparent-egress-inspection.md`. That is egress policy, not
this. The broker's argument never rested on the guest being CA-free; it rests
on the credential never entering the guest at all.)

Extracted 2026-08-12 from the session record that produced the broker. That
record is a narrative of one design session and covers two other subjects; it
lives outside this repository and does not resolve from a clean checkout. **This
file is authoritative for the current design.**

---

## 1. What this protects

The sandbox is trying to contain a specific failure: **the agent is
attacker-influenced.** Not necessarily compromised — just reading a repo, an
issue thread, or a web page written by someone else. Prompt injection is not an
exotic attack here, it is the normal operating condition.

Given that, rank the assets:

| Asset | Loss if the agent turns hostile |
|---|---|
| Provider API key | Permanent. Usable from anywhere, forever, until noticed and rotated. |
| Host account | Severe but bounded — recoverable with effort. |
| The LAN behind the host | Lateral movement into everything else. |
| Mounted source | Read once, exfiltrated forever. |
| The prompt channel itself | **Unclosable.** See below. |

The API key is worth the most and is also the *easiest* to protect, because
unlike the others it does not need to be in the sandbox at all. That asymmetry
is the whole design.

**What nothing closes.** The agent talks to a model provider by design. An
injected agent can write anything it can read into a prompt. Exfiltration
through the model channel is structural — no sandbox addresses it. This design
accepts it, and the consequence is worth stating loudly:

> After you have a network boundary, the mount set is your real secret
> boundary. Egress is mediated and scoped; a filesystem passthrough is not.
> Mounting an entire projects directory hands an injected agent that entire
> directory.

If the data is too sensitive for the provider to see, it is too sensitive for
the agent to read, and the boundary you need is the mount set, not the network.

---

## 2. The finding: base-URL override decouples the two properties

Credential isolation looks like it has to be bought with L7 mediation. It does
not, and that is why this is 300 lines instead of 15,000.

The protocol-generic approach — terminate TLS in the host, substitute the
credential, re-encrypt — requires a CA in every guest, a full userspace network
stack, and it breaks certificate pinning. It has to work that way because it
cannot assume the software inside cooperates.

*Amended 2026-08-26:* a filtered VM now has all of that anyway, for egress
policy. It does not change the conclusion, and the reason is worth stating
plainly: the substitution is the expensive half. Reading a request to authorise
its host is bounded work; rewriting one to carry a credential means knowing the
provider's auth scheme, keeping up with it, and holding the key on a path that
parses guest-controlled bytes. The broker holds the key on a path that parses
nothing of the guest's beyond a request line — and it is 300 lines because of
that, not because the guest has no CA.

**You can assume cooperation.** You control the guest image, and every agent SDK
honours a base-URL override. So:

- Guest env points the client at the broker
- The broker forwards to the real API, attaching the real key on the way out
- Guest → broker is plain HTTP on an address only that guest can reach;
  broker → provider is ordinary verified TLS from the host

No interception on this path. No pinning breakage. The agent never holds a
credential — the single property that matters most, and the only one of the four
that depends on nothing else being configured.

*Amended at rung 6:* **cooperation is no longer assumed, and that is strictly
stronger.** The step above that needed it — the guest pointing its client
somewhere — was the one thing an injected agent could undo, by pointing the
client back at the origin with a key it had found elsewhere, or simply by
running software that reads a base URL from somewhere the image does not set.
The redirect does not ask. The guest dials the provider's real name and the
inspector decides, so an agent that ignores every variable in its environment
reaches the broker anyway. What the finding bought is unchanged and still the
reason this is ~600 lines rather than 15,000: the broker parses nothing of the
guest's request beyond its line and headers, and it is the inspector — which
holds no credential — that does the reading.

**This does not replace network policy.** The broker covers exactly one
destination. Everything else the agent reaches — git, package registries,
whatever it decides to curl — still needs default-deny egress, or you have
protected the API key while leaving every exfiltration path open. That companion
work exists in workloadctl — per-VM default-deny keyed on the workload uid,
plus a transparent per-workload egress inspector for hostname policy — and
merged 2026-08-12. The inspector replaced the CONNECT proxy this paragraph
originally named: a proxy only filters a guest that is configured to use it,
and the redirect does not ask.

---

## 3. What the broker is, and is not

A reverse proxy that holds a workload's credentials and speaks only to the
upstreams its own config names.

**Deliberately not a general proxy.** The set of upstreams is fixed by config
and is *never* taken from the request. Absolute-form request targets
(`GET https://elsewhere/...`, which is how a client asks a proxy to choose a
destination) are rejected with 400. A broker that forwarded to a guest-chosen
destination would be an SSRF pivot with a credential welded to it — precisely
the failure this design exists to avoid, and a failure found in the field.

**This claim is qualified since rung 6, not abandoned.** The broker no longer
holds one credential for one upstream: it holds a table keyed by `Host`, and
the inspector supplies the `Host` of the request it is relaying. So a value
that originated in the guest now selects a row. What is preserved is the part
that carries the security property — **the guest can only select among rows the
host wrote**, and every row's `upstream` is configuration. A `Host` naming no
row is a 403, not a fetch. The guest gained the ability to pick a losing ticket
out of a hat the operator filled; it did not gain the ability to write one.

Decisions worth not re-litigating:

- **Credential headers from the guest are stripped, not passed through.** The
  guest has no legitimate reason to set `authorization`, `x-api-key`, and
  friends — we supply the credential — and forwarding them would make the broker
  an open relay for whatever key a compromised sandbox happened to find.
- **Denylist, not allowlist, for the remaining headers.** Provider SDKs send
  version and beta headers that change faster than an allowlist stays current,
  and silently dropping one breaks requests in ways that are painful to debug.
  Everything genuinely dangerous is enumerated.
- **`read1()`, not `read()`.** Load-bearing. A plain `read(n)` blocks until it
  has `n` bytes or EOF, which turns a token-by-token stream into one silent
  pause followed by the whole answer at once. The agent still works; the
  interaction feels broken.
- **204/304 must not be framed as chunked.** Even a bare terminator is a
  protocol violation strict clients reject.
- **Bounded concurrency.** One thread per connection with no ceiling lets a
  sandbox in a loop exhaust host threads. Past the bound we refuse rather than
  queue, so the guest gets a fast error instead of a hang.
- **The credential comes from the systemd credential store**, read from
  `$CREDENTIALS_DIRECTORY` — tmpfs, 0400, owned by the service user, gone when
  the unit stops. Secrets delivered to the *host* side of the boundary, never
  into the workload.
- **No option to disable upstream TLS verification**, and there should not be
  one.

---

## 4. Client cooperation

Two client behaviours had to hold for the base-URL shape, and both were checked
against the source of three real coding agents. **Neither is load-bearing any
more** — §2 records why — but they are kept because the trust-store trap below
is not about the broker at all, and a filtered guest walks into it regardless.

**Base-URL override: universal.** All three expose it per-provider. This was the
mechanism the design rested on through rung 5. The guest sets nothing now.

**Certificate pinning: absent.** No pinning checks in any of the three. The wall
that would have killed the HTTPS variant is not there — and since rung 3 a
filtered guest's inspector terminates TLS by default, so this finding turned out
to matter for the inspector rather than for the broker.

**The operational trap is the trust store, and it is per-runtime, not
per-product.** None of these runtimes use the system trust store, so installing
a CA into the system anchors does nothing:

| Runtime | Variable | Semantics |
|---|---|---|
| Node / Bun | `NODE_EXTRA_CA_CERTS` | **appends** to the bundled roots |
| Python | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | **replaces** the bundle |

The asymmetry costs an hour if hit blind: point a Python client's
`SSL_CERT_FILE` at your CA alone and every *other* TLS connection it makes
breaks. It must be certifi's `cacert.pem` concatenated with your CA.

**Neither open question survived the shape change.** They were whether a
provider SDK refuses plain `http://`, and whether pointing a client at a broker
disturbs provider-attribution logic keyed on the base-URL hostname. The guest's
client now sees the provider's own `https://` origin and nothing else — the
substitution happens two hops away, after the inspector has already terminated
the connection — so both questions are moot rather than unanswered.

---

## 5. Identity: which sandbox is calling

**The old mechanism is dead.** `_identify()` mapped source IP to sandbox name,
which was sound while each guest sat on an isolated bridge at a pinned address.
workloadctl has since replaced that bridge with passt, which re-originates every
guest flow as a host socket — so **every VM now reaches a host service from the
same source address.** The lookup cannot discriminate, and permitting unknown
sources would make every guest the same caller rather than none.

**The replacement is the peer socket's owning uid.** passt runs as the
workload's own user, so the socket on the other end of an accepted connection is
owned by `_wl-<name>`. The kernel records that owner; `/proc/net/tcp` exposes
it. Match the mirror tuple — the row whose local address is our peer and whose
remote address is our local — and read the uid column. `pwd.getpwuid()` turns it
into the workload name, so config stays keyed on something readable.

**"Our local" is not simply the address we are bound to.** Under the retired
host redirect the guest dialled an advertised literal and the kernel rewrote the
destination in flight; the client's socket still recorded the address it
*dialled*. Matching only `getsockname()` found no row at all on precisely the
path that existed for — while every loopback test passed, because loopback is
the one route with nothing to translate. So the match takes a *set* of candidate
local endpoints: the bound address, and `SO_ORIGINAL_DST`, which recovers the
pre-translation destination. This asymmetry was measured before the map that
depended on it was written; see §9.

*Since rung 6 there is no translation left on this path* — the inspector dials
the broker's own bound address, so `getsockname()` matches and `SO_ORIGINAL_DST`
returns the same endpoint. The candidate set is kept rather than simplified
away: it costs one `getsockopt` per connection, and it is the difference between
this program tolerating a redirect in front of it and failing closed on every
request if one is ever put there.

This is the same primitive the rest of the sandbox rests on: workloadctl's
egress policy matches `meta skuid`, and the uid is assigned by the host and
unforgeable from inside the guest.

**Two ways it goes silently wrong.** Both leave the broker serving traffic
happily, just not discriminating — so a test that asserts "the request
succeeded" passes through either one:

- **A user namespace breaks it.** The uid column is translated through the
  *reader's* namespace, so an owner the reader does not map reads as the
  overflow uid, 65534. Every workload becomes the same caller — reproducing the
  exact failure passt caused. The service unit must not set `PrivateUsers=`.
  The rest of the hardening set is unaffected.
- **TIME_WAIT rows report uid 0**, which reads as "owned by root" rather than as
  no-answer. Only trust a row for a live connection, and fail closed.

**Alternatives considered.** `SO_PEERCRED` is AF_UNIX only. `SO_ORIGINAL_DST`
answers *what was dialled*, not *who dialled it* — the same literal for every
guest — so it is useless as identity, even though the match above depends on it
for something else.

**One of them was subsequently adopted, and the objection to it dissolved rather
than being overruled.** Giving each sandbox its own broker instance on its own
listen address was rejected here for two reasons: it reverts to
address-as-identity, and it collides with the per-workload proxy map. The second
reason expired when the proxy was retired (ADR 008), and the first was a
misreading — a per-instance broker does not *replace* uid identity with address
identity, it adds an address the uid check then has to agree with. §6's last
paragraph had already named that as the quiet advantage. So rung 6 split the
instances (ADR 007) and kept the uid check, which is why a broker that somehow
received a connection from the wrong workload would still refuse it.

**Identity and reachability are separate questions.** The uid answers *who is
calling*. Whether a given workload can reach the broker at all is answered by
address: each instance binds a loopback address derived from its own workload's
uid, inside 127/8, which no guest's packets reach and no other workload is told.
Cross-sandbox access is structurally unavailable rather than denied by a rule
that could be misconfigured. Keep both; they fail independently.

---

## 6. Per-sandbox credentials

Knowing the caller is what makes it possible to choose a credential per caller.
The whole tuple can vary — credential, upstream, auth header and format — so one
sandbox can run against a spend-capped key, another against a local inference
endpoint, another against a different provider entirely.

The SSRF property survives intact, because the *trusted* side still picks the
destination. The guest names nothing; absolute-form targets remain a 400.

**Rotation is not hot.** Credentials are decrypted into tmpfs at unit start and
not re-read, so changing one means restarting the broker.

**Blast radius runs the other way from process count.** A shared broker holding
N different keys means one bug leaks all N; a broker instance per sandbox holds
one key each. That argues for per-instance *once the keys differ* — the opposite
of the conclusion when every sandbox shares a single key.

Peer-uid identity does not force this choice, which is its quiet advantage. In a
shared broker the uid routes; in per-instance brokers it becomes an assertion —
*this connection is genuinely from the uid I am configured for* — which is a
check the address-based design could not make at all. Start shared, split later,
without redoing the mechanism.

**Split at rung 6, and the mechanism was indeed not redone.** Every workload
declaring credential material gets its own instance holding only its own keys,
and the dispatch key became `(uid, Host)` rather than `uid` alone — the second
half being what lets one workload hold credentials for several providers. The
uid half is now the assertion described above: the config names exactly one
sandbox, so a resolved caller that is not it is a 403 on a connection that
should have been impossible to open.

---

## 7. Host integration

What the host must provide, and what a request actually traverses.

**Nothing is advertised.** A workload declaring `[[vm.network.credential]]`
material gets a `workload-<name>-broker.service` written by the boot generator:
`DynamicUser=yes`, bound to `vm_broker_listen_address(uid)` — `127.129.0.0` plus
the workload's offset from `UID_MIN`, port 8081 — with a `broker.toml`
regenerated into `/run` at every start by `workload-vm-broker config <name>`.
Its only caller is that workload's own egress inspector.

A request therefore goes: guest → passt (re-originates as the workload uid) →
the nat redirect that sends every filtered guest's 80/443 to its inspector →
inspector, which terminates TLS, applies `methods`/`paths`/host policy, and
finds the matched policy entry names a `credential` → inspector dials the broker
on that loopback address → broker attaches the real key → provider.

The guest's leg is unchanged from any other inspected host. It asked for
`api.anthropic.com` and it gets the provider's answer; the branch happens
entirely on the host side of a connection the guest had already given up
control of.

**Two constants must agree**: this program's `listen_address`/`listen_port`
against what the generator renders and what the inspector dials
(`vm_broker_listen_address` / `VM_BROKER_INSTANCE_PORT` in `lib/vm.py`). A
mismatch presents exactly as the broker being down — connection refused, no log
line on either side, nothing pointing at the cause. `tests/test_vm_broker.py`
asserts they agree, which is most of the reason the broker moved into this
package.

Consequences worth knowing:

- **The broker's address needs an explicit nftables exemption**, and this is not
  obvious. `127.129.x.y` is inside 127/8, which is inside `wl_internal4`, and
  the cgroup-keyed drop that stops the inspector reaching host-internal ranges
  sits *above* the rule accepting its loopback traffic. So `workload-vm-inspect`
  arms the broker's address in `wl_internal_ok4` for any workload that has one.
  Without it the dial is dropped in silence and presents as a dead broker. This
  was found on hardware, not in review.
- **No `[[vm.network.allow]]` entry is needed** for the provider host on the
  brokered path, beyond the `[[vm.network.policy]]` entry that names the
  credential. The inspector never dials the origin for a brokered host at all.
- **The upstream leg is not attributable to the sandbox.** The broker egresses
  as its own dynamic user, outside the workload uid range, so the host's
  connection-marking rule does not tag it and per-workload packet capture will
  not show that half.
- **The broker's own egress is unfiltered** by the workload policy, for the same
  reason. That is correct — it is host infrastructure, not a workload — but it
  means the broker is the one component that can reach the provider directly,
  and it should be treated as such.
- **The workload uid cannot read its own broker's config.** The instance runs as
  a dynamic user disjoint from `_wl-<name>`, and `broker.toml` names the
  credential the instance loads. A workload that could read it would learn the
  seal name, which is the one thing standing between it and asking systemd for
  the material.

> **Retired at rung 6:** the `workload_broker` nftables table and its
> `wl_broker_dest` uid→address map, the advertised `192.0.2.1:8081` endpoint,
> the host-wide `agent-broker.service`, `/etc/agent-broker/`, and the
> `WORKLOAD_BROKER_URL` variable. `[vm.network].broker = true` is refused by
> `validate` by name, naming `credential` as the replacement. The address that
> carried all of it, `192.0.2.1`, is no longer put on the dummy link, and
> TEST-NET-1 consequently moved *into* `wl_internal4` — it had been excluded
> only because that address lived in it.

## 8. TLS to the guest, and the private-CA trap

`tls_cert`/`tls_key` serve HTTPS to the guest for clients that refuse plaintext
credentials. One certificate for one name from a private CA the guest trusts —
internal PKI, not interception. Most deployments will not need it.

`relax_x509_strict` exists for one specific failure: Python 3.13+ enables
`VERIFY_X509_STRICT`, which enforces RFC 5280's requirement that a CA
certificate carry a `keyUsage` extension with `keyCertSign`. A private root
without it is rejected with a message that reads like a missing trust anchor
rather than a malformed CA, and curl, Node and Bun all accept the same chain —
so the defect can sit undiscovered for years and then surface only inside a
sandbox, only for Python clients.

The option clears **only** that strictness flag. Chain building, signature
verification, expiry, and hostname matching all still apply. Fix the CA where
you can — re-issuing the root with the existing key preserves every existing
signature, so there is no cutover — and use this only where you cannot.

---

## 9. What was proven

A live end-to-end run against a real authenticated upstream, from a client
launched with `env -i` — literally zero environment variables:

| | Result |
|---|---|
| via broker | **200** + real response |
| direct to the upstream | **401** |
| client sends a forged `Bearer` token via broker | **200** — forged value discarded, real one substituted |
| same forged value, direct | **401** |

The key arrived through the systemd credential store, decrypted into tmpfs at
0400, and vanished when the unit stopped. Broker logs show the request and
status with no credential material anywhere in them.

So the key can be kept out of the coding tool. The tool holds nothing, cannot be
tricked into supplying its own, and can reach only the one upstream the broker
is configured for.

The peer-uid mechanism was separately verified 2026-08-12: recovered against a
live socket from the real kernel tables, and end to end through the request
path, where two runs differing only in configuration produced a resolved caller
and a refusal on the same connection. Both silent-failure modes have tests.

**The redirect's shape was measured, not assumed** — the rule was built in a
network namespace and the socket tables read through it, before the host map
that depends on them was written:

```
client row   local=192.0.2.1:58224  rem=192.0.2.1:8081   <- the address it dialled
server       getsockname()=127.0.0.1:8081                <- what the match used
```

Comparing against `getsockname()` alone would have matched nothing and returned
403 to every guest, while passing every loopback test for the reason given in
§5. Verified again through the whole path afterwards: with a map element, a
resolved caller and a 502 from the deliberately bogus upstream; with the element
removed, connection refused.

One correction from building it. The startup guard first demanded the initial
namespace's uid map, which was wrong in the direction that matters least but
annoys most: a container can be namespaced and still map the whole workload
range, and refusing there is a false alarm — the kind an operator learns to
route around, taking the real check with it. The guard now resolves each
configured sandbox's uid and asks whether *that* is mappable, which is both
exact and actionable, and warns rather than refuses when it has nothing to
check.

---

## 10. Running it

The broker ships in the workloadctl RPM and therefore in the hypervisor image:
the program at `/usr/libexec/workloadctl/agent-broker`, this file and an
annotated `agent-broker.toml.example` under `/usr/share/doc/workloadctl/`.

**There is no unit to enable and no config to edit.** Since rung 6 there is no
host-wide `agent-broker.service` and no `/etc/agent-broker/`: an instance is
generated per workload from that workload's own TOML, and starts and stops with
it. Turning it on is two steps in the workload, not three on the host:

```bash
# 1. seal the material under the workload's own scope
workloadctl secret create broker/agent-vm/anthropic

# 2. declare it, and name it from the policy entries it applies to
$EDITOR /etc/workloads.d/agent-vm/workload.toml
workloadctl validate agent-vm && workloadctl enable agent-vm
```

```toml
[[vm.network.policy]]
host       = "api.anthropic.com"
methods    = ["POST"]
paths      = ["/v1/messages"]
credential = "anthropic"

[[vm.network.credential]]
name        = "anthropic"
placeholder = "sk-ant-placeholder-not-a-real-key"
env         = "ANTHROPIC_API_KEY"
```

One name is spelled twice and both must agree: the last segment of the
`secret create` path, and `name` in the credential block. workloadctl derives
the seal name (`broker-<workload>-<name>`) and the unit's
`LoadCredentialEncrypted=` from those, so there is no third place to get wrong —
and because systemd-creds binds the seal name into the blob and verifies it on
decrypt, a unit handed another workload's file fails at start rather than
loading that workload's key.

Configuration that matters, beyond the comments in the example:

- **The set of upstreams is fixed and never taken from a request**, and the
  qualification in §3 applies: a `Host` selects among rows the host wrote, and
  one naming no row is a 403. Absolute-form request targets are rejected with
  400.
- **`[sandboxes.<workload-name>]` is keyed by workload name**, resolved from the
  uid owning the far end of the connection (§5). A generated config has exactly
  one, and anything else gets 403.
- **The unit must not set `PrivateUsers=`.** From a user namespace that cannot
  map a workload's uid, every caller reads as the overflow uid and they all
  merge into one identity, with no error anywhere. The broker refuses to start
  when it can prove this is happening and warns when it cannot. The generated
  unit does not set it; this matters if you write one by hand.
- **Credentials are read at start and not re-read**, so rotating one means
  restarting that workload's broker instance. Editing the workload's TOML
  regenerates `broker.toml` at the next start, so a changed `auth_header` or
  `upstream` needs the same restart.
- **`relax_x509_strict`** exists for private CAs missing `keyUsage`, which
  Python 3.13+ rejects (§8). Do not set it without a reason.
- **A key the broker does not read is a startup error**, at the top level and
  inside `[sandboxes.<name>]` alike, with the nearest real key suggested. Every
  option here decides who receives a credential or how the guest is served, so
  a typo that silently falls back to the default gives an operator a broker
  that starts, looks healthy, and applies a policy they did not pick. `validate`
  catches these before the generator writes a unit; the broker's own check is
  what covers a hand-written config.
- **`allow_unknown_callers` is for local testing and logs a warning at
  startup.** The generator never emits it.

**Broker material is not carried by `backup`.** `workloadctl backup` copies a
workload's `data/` subtree and the credentials its own config references; the
sealed provider keys under `broker/<workload>/` are outside that set, by
decision rather than by oversight. They are sealed to the host — TPM2, or
`/var/lib/systemd/credential.secret` — so the ciphertext would not decrypt on
another machine even if it were copied, and an archive that appeared to contain
a provider key would be a worse artefact to hand around than one that plainly
does not. Re-seal them on the restore host with `secret create`.

### What the broker refuses, and why a client might see it

| | |
|---|---|
| `403` | The caller resolved to no configured sandbox — or could not be resolved at all, which is never rescued by `allow_unknown_callers` (§5). |
| `400` | An absolute-form request target (that is a *proxy's* job, not this one's); a `Content-Length` that is not a non-negative number; or two of them, which frame two different messages. |
| `411` | A chunked request body. The broker does not decode one, and forwarding it as an empty body — which is what it used to do — meant the provider answered a request the caller never sent. Send `Content-Length`. |
| `413` | A body over 64 MiB. |
| `503` | The broker is already holding 256 MiB of request bodies for other callers. Retryable, and not about this request: 64 MiB is legal for any one of them, so it is the sum that is refused. |

Every refusal closes the connection: a rejected request has left its body
unread, so the next bytes on the wire are body where a request line should be.

A connection may also be closed with no reply at all. That is the admission
bound: 32 concurrent connections in total, and 8 for any one caller. The
per-caller ceiling is the one that matters — without it a single sandbox
opening 32 sockets, sending nothing, denied the broker to every other sandbox
on the host. Connections that make no progress for 60 seconds are dropped, so
holding one open costs a caller something.

Memory is bounded separately from connections, because a request body is
buffered whole before it goes upstream and neither of the connection limits
says anything about size. 256 MiB across all callers at once, reserved on the
declared `Content-Length` before the bytes are read. This is a hypervisor: the
RAM a sandboxed agent would be reaching for is RAM the VMs are using.

An upstream that fails is `502` — but only while the broker still owns the
response. Once the upstream's own status and headers have gone to the caller,
a failure part-way through the body cannot be reported as a status, because
one is already sent; writing a 502 there puts a whole second response *inside
the first one's body*, which a caller reads as content. So the connection is
dropped instead, leaving a body short of its `Content-Length` or a chunked body
with no terminating chunk. Both are truncated messages by definition, which is
what makes a client raise rather than hand a half-finished completion to the
agent as if it were the whole answer. In the log the two cases are one event
with `streamed=` telling them apart.

### What the guest does with it

**Nothing, and that is the point.** The guest is handed no endpoint and no
variable naming the broker. Its client is configured for the provider exactly as
it would be without one — real hostname, real port — and the only unusual thing
in its environment is that the API-key variable holds `placeholder` instead of a
key.

That variable is required, and it is the one piece of guest-side configuration
the design still needs: an SDK that refuses to send a request without a key
fails inside the guest, before a packet, which looks nothing like a policy
failure. `env` in the credential block names it, and workloadctl seeds it into
the guest env:

```toml
[[vm.network.credential]]
name        = "anthropic"
placeholder = "sk-ant-placeholder-not-a-real-key"
env         = "ANTHROPIC_API_KEY"
```

The broker discards whatever arrives in the auth header and sets the real
value, so the placeholder never reaches the provider. It must not be a real
key — the broker refuses to start if it equals the decrypted material, which is
the check for one having been pasted into a world-readable `workload.toml`.

A filtered guest does need the inspector's CA, which is a separate matter
handled by workloadctl's own guest env; read §4 before touching a trust-store
variable by hand, because `NODE_EXTRA_CA_CERTS` appends and `SSL_CERT_FILE`
replaces.

For local development the program takes its config path as its only argument and
falls back to `AGENT_BROKER_SECRET` for the credential, logging a warning:

```bash
AGENT_BROKER_SECRET='sk-...' /usr/libexec/workloadctl/agent-broker /tmp/b.toml
```

Set `allow_unknown_callers = true` for that, since a caller from your own login
is not a workload user and matches no sandbox.

---

## 11. What is not built

- **No consumer.** No deployed workload declares credential material, and there
  is no sandbox VM and no guest image. The feature still has zero users — which
  is what made rung 6 free to delete the host-wide shape outright rather than
  migrate it. The two workloads the rig stands up are throwaways it creates and
  destroys.
- **Nothing runs the end-to-end check but a person.** The seam is proven (see
  below) by a rig needing root and two VMs of its own, so it is neither a PR
  gate nor part of the runtime rung. A regression in it surfaces when someone
  next runs it by hand, not when it is introduced. This gap is why five defects
  reached hardware at rung 6 having passed the whole unit suite.

Built 2026-08-12: peer-uid identification, per-sandbox credential and upstream
profiles, the startup guard for the namespace failure, a test suite that asserts
on recovered uids rather than on response codes, and the host-side uid-keyed
redirect described in §7. Packaged 2026-08-13 into the workloadctl RPM, which
answered the open question of where it lives: not a workload — being precisely
what workloads are not trusted with — but shipped by the thing that manages
them, on the host, in the image.

**Superseded at rung 6.** What follows records a real run against the shape
described above, and that shape is gone: the advertised literal, the redirect
map and the single host-wide listener were deleted, and the rig with them (see
`tests/manual/README.md`). It is kept because it is the evidence the design
rested on and deleting it would leave the claims below looking unproven rather
than re-scoped. Its replacement ran on 2026-09-02, 35/35 on a KVM host under
enforcing, and closed the end-to-end claim for the new shape — after finding
five defects that no unit test could see, two of which made the brokered path
inert on a real guest. See `tests/manual/README.md`.

Proven end to end 2026-08-14 on a KVM host, against the installed RPM rather
than a checkout: `tests/manual/broker_rig.py`, 18/18. Four guests differing by
one line of config each, so the claims come apart — two dialled the same
advertised literal and were told apart by the uid owning the socket, each
receiving its own credential; the guest without `broker = true` could not
connect at all, holding no element of the redirect map; and forcing the proxy
with `NO_PROXY` cleared reproduced the pre-fix 403, confirming the default path
does not traverse the proxy. Before this, the path in §7 had only ever been
proven a segment at a time — the redirect in a namespace, identity against live
kernel tables, the broker against a real upstream — which is what let two
defects live in the *combinations*: a client recording the address it dialled
rather than the one the broker is bound to, and a guest with both a proxy and a
broker sending its broker request through the proxy.

The second of those two is now structurally impossible rather than fixed. The
per-workload proxy was retired on 2026-08-25 (ADR 008): a filtered guest is no
longer told to route anything, so there is nothing for a broker request to be
routed *through*, and the `NO_PROXY` entry that held the two apart is gone with
it. The rig assertion that forced the old path is kept above as the record of
what it caught.
