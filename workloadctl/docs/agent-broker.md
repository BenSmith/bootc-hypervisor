# The credential broker

`libexec/agent-broker` — why this program exists, what it refuses to do, how it
knows which sandbox is calling, and how to run it.

A sandboxed coding agent never receives a provider API key. It points its client
at the broker with a base-URL override; the broker attaches the real credential
on the way out. Guest → broker is plain HTTP over an isolated path; broker →
provider is ordinary verified TLS from the host. No CA in the guest, no TLS
interception, nothing that breaks certificate pinning.

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

**You can assume cooperation.** You control the guest image, and every agent SDK
honours a base-URL override. So:

- Guest env points the client at the broker
- The broker forwards to the real API, attaching the real key on the way out
- Guest → broker is plain HTTP on an address only that guest can reach;
  broker → provider is ordinary verified TLS from the host

No CA in the guest. No interception. No pinning breakage. The agent never holds
a credential — the single property that matters most.

**This does not replace network policy.** The broker covers exactly one
destination. Everything else the agent reaches — git, package registries,
whatever it decides to curl — still needs default-deny egress, or you have
protected the API key while leaving every exfiltration path open. That companion
work exists in workloadctl (per-VM default-deny keyed on the workload uid, plus
a per-workload CONNECT proxy for hostname policy) and merged 2026-08-12.

---

## 3. What the broker is, and is not

A reverse proxy that holds one credential and speaks to one upstream.

**Deliberately not a general proxy.** The upstream is fixed by config and is
*never* taken from the request. Absolute-form request targets
(`GET https://elsewhere/...`, which is how a client asks a proxy to choose a
destination) are rejected with 400. A broker that forwarded to a guest-chosen
destination would be an SSRF pivot with a credential welded to it — precisely
the failure this design exists to avoid, and a failure found in the field.

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

Two client behaviours have to hold. Both were checked against the source of
three real coding agents.

**Base-URL override: universal.** All three expose it per-provider. This is the
mechanism the whole design rests on and it is not in doubt.

**Certificate pinning: absent.** No pinning checks in any of the three. The wall
that would have killed the HTTPS variant is not there.

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

**Practical order: try plain HTTP first.** All three take a base URL and you may
never need a CA at all. Only if a client refuses to send credentials over
plaintext do you reach for `tls_cert`/`tls_key`, and that is the easy sub-case —
one hostname, one certificate.

Two things static reading could not answer: whether any provider SDK *refuses*
plain `http://` (that check lives in the vendored client libraries), and whether
pointing a client at a broker disturbs any provider-attribution logic that
matches on the base-URL hostname.

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

**"Our local" is not simply the address we are bound to.** Under the host
redirect the guest dials an advertised literal and the kernel rewrites the
destination in flight; the client's socket still records the address it
*dialled*. Matching only `getsockname()` finds no row at all on precisely the
path this exists for — while every loopback test passes, because loopback is the
one route with nothing to translate. So the match takes a *set* of candidate
local endpoints: the bound address, and `SO_ORIGINAL_DST`, which recovers the
pre-translation destination. This asymmetry was measured before the map that
depends on it was written; see §9.

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
guest — so it is useless as identity, even though the match above now depends on
it for something else. Giving each sandbox its own broker instance on its own
listen address would work, but it reverts to address-as-identity, and it
collides with the existing per-workload proxy map (one value per uid, one
advertised endpoint) rather than composing with it.

**Identity and reachability are separate questions.** The uid answers *who is
calling*. Whether a given workload can reach the broker at all is answered by
whether it has an element in the host's redirect map — no element, no
translation, nothing listening at the advertised address. Cross-sandbox access
is then structurally unavailable rather than denied by a rule that could be
misconfigured. Keep both; they fail independently.

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

---

## 7. Host integration

What the host must provide, and what a request actually traverses.

The guest is handed a fixed advertised endpoint — an address literal on a
host-side interface no guest can otherwise reach. A nat output rule rewrites
that one destination per uid, using a map from uid to the real listener. The
guest cannot influence the translation: it only ever dials the literal.

A request therefore goes: guest → passt (re-originates as the workload uid) →
nat output rewrites the destination → filter output, which sees the translated
destination on loopback and accepts it under the rule that exempts a workload's
own control plane → broker.

**The host half is built** as a `workload_broker` nftables table holding a
`wl_broker_dest` map from uid to address and port. A workload opts in with
`broker = true` in its VM network section; the VM unit adds and removes that
workload's element around the guest's lifetime (`libexec/workload-vm-broker`),
and the guest is told the endpoint through a `WORKLOAD_BROKER_URL` environment
variable. It is deliberately a separate table from the per-workload proxy's: a
workload may want a broker and no proxy, and would otherwise depend on a
skeleton applied by a unit it does not run.

**Two constants must agree**: this program's `listen_address`/`listen_port`
defaults against the address and port the map's elements carry
(`VM_BROKER_LISTEN_ADDR`/`VM_BROKER_LISTEN_PORT` in `lib/vm.py`). A mismatch
presents exactly as the broker being down — connection refused, no log line on
either side, nothing pointing at the cause. They were a cross-repo constant
checked by neither side until the broker moved into this package;
`tests/test_vm_broker.py` now asserts they agree, which is most of the reason it
moved.

Consequences worth knowing:

- **No allowlist entry is needed** for the broker endpoint. The loopback
  exemption already covers it, for the same reason it covers the existing
  per-workload proxy.
- **The upstream leg is not attributable to the sandbox.** The broker egresses
  as its own service identity, outside the workload uid range, so the host's
  connection-marking rule does not tag it and per-workload packet capture will
  not show that half.
- **The broker's own egress is unfiltered** by the workload policy, for the same
  reason. That is correct — it is host infrastructure, not a workload — but it
  means the broker is the one component that can reach the provider directly,
  and it should be treated as such.

---

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
the program at `/usr/libexec/workloadctl/agent-broker`, the unit as
`agent-broker.service`, this file and an annotated `agent-broker.toml.example`
under `/usr/share/doc/workloadctl/`, and an empty root-only `/etc/agent-broker/`
for the config and credentials.

It is **not enabled**. No preset line names it and it cannot start without a
config, so a host that installs workloadctl gets an inert unit. Three steps turn
it on:

```bash
cp /usr/share/doc/workloadctl/agent-broker.toml.example /etc/agent-broker/broker.toml
$EDITOR /etc/agent-broker/broker.toml          # upstream, and one entry per sandbox
systemd-creds encrypt --name=anthropic-api-key - \
    /etc/agent-broker/anthropic-api-key.cred
systemctl enable --now agent-broker
```

One name is spelled three times and all three must agree: `--name=` above, the
name in the unit's `LoadCredentialEncrypted=`, and `credential =` in
broker.toml. `--name=` is sealed into the blob and verified on decrypt, so every
mismatch fails at start rather than at request time. The blobs live in
`/etc/agent-broker/` rather than `/etc/credstore.encrypted/`, which is a flat
namespace shared with every unit on the host — including workloadctl's own
workload credentials.

Configuration that matters, beyond the comments in the example:

- **`upstream` is fixed and never taken from a request.** That is the security
  property; absolute-form request targets are rejected with 400.
- **`[sandboxes.<workload-name>]` is keyed by workload name**, resolved from the
  uid owning the far end of the connection (§5). Anything unlisted gets 403.
  Each sandbox inherits the top-level settings and may override any of them, so
  sandboxes can hold different keys or target different providers.
- **The unit must not set `PrivateUsers=`.** From a user namespace that cannot
  map a workload's uid, every caller reads as the overflow uid and they all
  merge into one identity, with no error anywhere. The broker refuses to start
  when it can prove this is happening and warns when it cannot.
- **Credentials are read at start and not re-read**, so rotating one means
  restarting the unit. The unit is also restarted by any workloadctl upgrade
  that finds it running, so the process never outlives the code that was
  installed.
- **`relax_x509_strict`** exists for private CAs missing `keyUsage`, which
  Python 3.13+ rejects (§8). Do not set it without a reason.
- **A key the broker does not read is a startup error**, at the top level and
  inside `[sandboxes.<name>]` alike, with the nearest real key suggested. Every
  option here decides who receives a credential or how the guest is served, so
  a typo that silently falls back to the default gives an operator a broker
  that starts, looks healthy, and applies a policy they did not pick.
- **`allow_unknown_callers` is for local testing and logs a warning at
  startup.** With it off, a caller needs to be both routed here (a map element,
  added by its own VM unit) and named in `[sandboxes]`, so neither list alone
  grants a credential. With it on, the map is the only thing left — and map
  elements are keyed by uid, which workloadctl reuses.

### What the broker refuses, and why a client might see it

| | |
|---|---|
| `403` | The caller resolved to no configured sandbox — or could not be resolved at all, which is never rescued by `allow_unknown_callers` (§5). |
| `400` | An absolute-form request target (that is a *proxy's* job, not this one's); a `Content-Length` that is not a non-negative number; or two of them, which frame two different messages. |
| `411` | A chunked request body. The broker does not decode one, and forwarding it as an empty body — which is what it used to do — meant the provider answered a request the caller never sent. Send `Content-Length`. |
| `413` | A body over 64 MiB. |

Every refusal closes the connection: a rejected request has left its body
unread, so the next bytes on the wire are body where a request line should be.

A connection may also be closed with no reply at all. That is the admission
bound: 32 concurrent connections in total, and 8 for any one caller. The
per-caller ceiling is the one that matters — without it a single sandbox
opening 32 sockets, sending nothing, denied the broker to every other sandbox
on the host. Connections that make no progress for 60 seconds are dropped, so
holding one open costs a caller something.

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

Every guest is handed the same advertised literal in `WORKLOAD_BROKER_URL`
(§7); the host rewrites it per uid to that sandbox's broker. The guest image
maps it to whatever its agent actually reads — one line of cloud-init, and it
belongs with the software that has an opinion about the spelling:

```bash
ANTHROPIC_BASE_URL=$WORKLOAD_BROKER_URL            # Node/Bun agents
# Python agents: base_url in the provider config
```

Add a trust-store variable only if you serve HTTPS to the guest, and read §4
before you do: `NODE_EXTRA_CA_CERTS` appends, `SSL_CERT_FILE` replaces.

For local development the program takes its config path as its only argument and
falls back to `AGENT_BROKER_SECRET` for the credential, logging a warning:

```bash
AGENT_BROKER_SECRET='sk-...' /usr/libexec/workloadctl/agent-broker /tmp/b.toml
```

Set `allow_unknown_callers = true` for that, since a caller from your own login
is not a workload user and matches no sandbox.

---

## 11. What is not built

- **No guest has ever dialled it.** The path in §7 has been proven a segment at
  a time — the redirect in a namespace, identity against live kernel tables, the
  broker against a real upstream — but never once end to end from an actual VM.
  `tests/manual/broker_rig.py` is the rig that would close this; it has not been
  run. Until it has, treat the seam as untested however green the suites are.
- **No consumer.** No workload sets `broker = true`, and there is no sandbox VM
  and no guest image. The feature has zero users.

Built 2026-08-12: peer-uid identification, per-sandbox credential and upstream
profiles, the startup guard for the namespace failure, a test suite that asserts
on recovered uids rather than on response codes, and the host-side uid-keyed
redirect described in §7. Packaged 2026-08-13 into the workloadctl RPM, which
answered the open question of where it lives: not a workload — being precisely
what workloads are not trusted with — but shipped by the thing that manages
them, on the host, in the image.
