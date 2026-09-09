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
pointed at another workload's. The broker's own path involves no TLS
interception and breaks no
certificate pinning. (A *filtered* VM does carry a CA for a different
reason — its egress inspector terminates TLS by default; see
`adr/008-transparent-egress-inspection.md`. That is egress policy, not
this. The broker's argument does not rest on the guest being CA-free; it rests
on the credential never entering the guest at all.)

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

## 2. Why this is ~600 lines and not 15,000

Credential isolation looks like it has to be bought with full L7 mediation —
terminate TLS, parse the request, know the provider's auth scheme, rewrite the
header, re-encrypt. It does not, and the reason is a split of labour.

**Reading a request to authorise it and rewriting it to carry a credential are
very different jobs.** Authorising is bounded: a host, a method, a path.
Substituting means knowing each provider's auth scheme, keeping up with it, and
holding a key on a code path that parses guest-controlled bytes. This design
puts those two jobs in two programs. The egress inspector does the reading and
holds no credential; the broker holds the credential and parses nothing of the
guest's request beyond its line and headers. Neither program is the expensive
one, which is why there is no 15,000-line TLS-rewriting middlebox here.

**Nothing is asked of the guest.** The obvious cheaper design — point the
client at the broker with a base-URL environment variable — works, and every
agent SDK honours such an override. It is not what this does, because that step
is exactly the one an attacker-influenced agent can undo: point the client back
at the origin with a key found elsewhere, or just run software that reads its
base URL from somewhere the image does not set. Here the guest dials the
provider's real name and **the host decides**, so an agent that ignores every
variable in its environment reaches the broker anyway.

So the path is: no interception between broker and provider, no pinning
breakage, and the agent never holds a credential — the property that matters
most, and the only one that depends on nothing else being configured correctly.

**This does not replace network policy.** The broker covers exactly one
destination. Everything else the agent reaches — git, package registries,
whatever it decides to curl — still needs default-deny egress, or you have
protected the API key while leaving every exfiltration path open. That companion
work exists in workloadctl — per-VM default-deny keyed on the workload uid,
plus a transparent per-workload egress inspector for hostname policy. An
inspector rather than a CONNECT proxy: a proxy only filters a guest that is
configured to use it, and the redirect does not ask.

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

**One qualification, because it is easy to misread as a hole.** The broker
holds a *table* of credentials keyed by `Host`, and the inspector supplies the
`Host` of the request it is relaying — so a value that originated in the guest
does select a row. What carries the security property is that **the guest can
only select among rows the host wrote**: every row's `upstream` is
configuration, and a `Host` naming no row is a 403, not a fetch. The guest can
pick a losing ticket out of a hat the operator filled; it cannot write one.

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

## 4. The trust-store trap in the guest

Nothing here is about the broker — the broker's leg to the provider is ordinary
TLS from the host. It is about the guest, because a *filtered* guest's egress
inspector terminates TLS and the guest must trust the inspector's CA. This is
the failure people lose an afternoon to.

**Certificate pinning is not the obstacle.** The source of three real coding
agents was checked and none of them pins; a terminating inspector in front of
them works.

**The trap is the trust store, and it is per-runtime, not per-product.** None of
these runtimes use the system trust store, so installing a CA into the system
anchors does nothing:

| Runtime | Variable | Semantics |
|---|---|---|
| Node / Bun | `NODE_EXTRA_CA_CERTS` | **appends** to the bundled roots |
| Python | `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | **replaces** the bundle |

The asymmetry costs an hour if hit blind: point a Python client's
`SSL_CERT_FILE` at your CA alone and every *other* TLS connection it makes
breaks. It must be certifi's `cacert.pem` concatenated with your CA.

Two questions that would matter for a base-URL design do not arise here:
whether a provider SDK refuses plain `http://`, and whether pointing a client at
a different hostname disturbs provider-attribution logic. The guest's client
sees the provider's own `https://` origin and nothing else — the substitution
happens two hops away, on the far side of a connection the inspector has already
terminated.

---

## 5. Identity: which sandbox is calling

**Source address cannot answer this**, which is worth saying first because it
is the obvious mechanism. Workload networking is passt, which re-originates
every guest flow as a host socket, so **every VM reaches a host service from the
same source address.** An address lookup cannot discriminate, and permitting
unknown sources would make every guest the same caller rather than none.

**The caller is identified by the peer socket's owning uid.** passt runs as the
workload's own user, so the socket on the other end of an accepted connection is
owned by `_wl-<name>`. The kernel records that owner; `/proc/net/tcp` exposes
it. Match the mirror tuple — the row whose local address is our peer and whose
remote address is our local — and read the uid column. `pwd.getpwuid()` turns it
into the workload name, so config stays keyed on something readable.

**"Our local" is a set, not simply the address we are bound to.** On the path
as configured the inspector dials the broker's own bound address, so
`getsockname()` is the right answer. But if a DNAT rule is ever put in front of
the broker, the client's socket records the address it *dialled*, and the row
matched on `getsockname()` alone does not exist — identification then fails on
every request while every loopback test still passes, because loopback is the
one route with nothing to translate. So the match takes a set of candidate local
endpoints: the bound address, and `SO_ORIGINAL_DST`, which recovers a
pre-translation destination. It costs one `getsockopt` per connection and is the
difference between tolerating a redirect and failing closed under one. The
asymmetry was measured rather than assumed; see §9.

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

**Alternatives that do not work.** `SO_PEERCRED` is AF_UNIX only.
`SO_ORIGINAL_DST` answers *what was dialled*, not *who dialled it* — the same
endpoint for every guest — so it is useless as identity, even though the match
above depends on it for something else.

**Per-instance listen addresses do not replace this check, they add to it.**
Each broker binds an address derived from its own workload's uid (§7), which
might look like a return to address-as-identity. It is not: the address decides
who can reach the instance, and the uid check then decides whether the caller on
that connection is the one workload the instance is configured for. A broker
that somehow received a connection from the wrong workload still refuses it.

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

**So the deployment is one instance per workload.** Every workload declaring
credential material gets its own broker holding only its own keys, and the
dispatch key is `(uid, Host)` — the `Host` half is what lets one workload hold
credentials for several providers, and the uid half is an assertion rather than
a route: the config names exactly one sandbox, so a resolved caller that is not
it is a 403 on a connection that should have been impossible to open.

Peer-uid identity is what makes that split cheap. It works unchanged whether the
uid *routes* (a shared broker choosing among callers) or merely *asserts* (an
instance confirming its one caller) — a check an address-based design could not
make at all.

---

## 7. Host integration

What the host must provide, and what a request actually traverses.

**Nothing is advertised.** A workload declaring credential material — a VM's
`[[vm.network.credential]]` or a container's `[[network.credential]]`; one
mechanism, described below in the VM's terms — gets a
`workload-<name>-broker.service` written by the boot generator:
`DynamicUser=yes`, bound to `vm_broker_listen_address(uid)` — `127.129.0.0` plus
the workload's offset from `UID_MIN`, port 8081 — with a `broker.toml`
regenerated into `/run` at every start by `workload-vm-broker config <name>`.
Its only caller is that workload's own egress inspector.

A request therefore goes: guest → passt (re-originates as the workload uid) →
the nat redirect that sends every filtered guest's 80/443 to its inspector →
inspector, which terminates TLS, applies `methods`/`paths`/host policy, and
finds the matched policy entry names a `credential` → inspector dials the broker
on that loopback address → broker attaches the real key → provider.

**A container takes the same path with two substitutions**: the workload's own
container-network stack in place of passt (the traffic is re-originated by a
host process owned by the same workload uid either way, which is what makes the
uid the selector on both), and `workload-container-inspect` in place of
`workload-vm-inspect` for the nftables arming. Everything from the redirect
onward — the inspector, the policy match, the dial to `127.129.x.y`, the broker
— is the same code reading the same document. The one thing that is genuinely
different is unit ordering: in pod and bridge mode the workload umbrella is
`After=` its member containers, so the broker is ordered before the pod/net
head unit rather than before the umbrella. Ordered before the umbrella it would
start after every container already had, and the first brokered request in that
window is refused while every unit reads healthy.

The guest's leg is unchanged from any other inspected host. It asked for
`api.anthropic.com` and it gets the provider's answer; the branch happens
entirely on the host side of a connection the guest had already given up
control of.

**Two constants must agree**: this program's `listen_address`/`listen_port`
against what the generator renders and what the inspector dials
(`vm_broker_listen_address` in `lib/workload_addr.py`, `VM_BROKER_INSTANCE_PORT`
in `lib/broker_config.py`). A
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
  Without it the dial is dropped in silence and presents as a dead broker.
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

> **There is no host-wide broker and no advertised endpoint.**
> `[vm.network].broker = true` is refused by `validate` by name, naming
> `credential` as the replacement: it asks for one shared broker at an address
> the guest is told about, which is a weaker shape than the per-workload
> instance the guest cannot name.

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

The peer-uid mechanism is verified separately: recovered against a live socket
from the real kernel tables, and end to end through the request path, where two
runs differing only in configuration produce a resolved caller and a refusal on
the same connection. Both silent-failure modes have tests.

**The behaviour under a DNAT rule was measured, not assumed**, which is what
justifies carrying the candidate set in §5 rather than matching `getsockname()`
alone. The rule was built in a network namespace and the socket tables read
through it:

```
client row   local=192.0.2.1:58224  rem=192.0.2.1:8081  <- what it dialled
server       getsockname()=127.0.0.1:8081                 <- what a naive match uses
```

The two do not meet, so `getsockname()` alone matches nothing and returns 403 to
every caller — while passing every loopback test, for the reason given in §5.

The startup guard resolves each configured sandbox's uid and asks whether
*that* is mappable, rather than demanding the initial namespace's uid map: a
container can be namespaced and still map the whole workload range, so the
broader check is a false alarm — the kind an operator learns to route around,
taking the real check with it. It warns rather than refuses when it has
nothing to check.

---

## 10. Running it

The broker ships in the workloadctl RPM and therefore in the hypervisor image:
the program at `/usr/libexec/workloadctl/agent-broker`, this file and an
annotated `agent-broker.toml.example` under `/usr/share/doc/workloadctl/`.

**There is no unit to enable and no config to edit.** There is no host-wide
`agent-broker.service` and no shared config directory: an instance is generated
per workload from that workload's own TOML, and starts and stops with it.
Turning it on is two steps in the workload, none of them on the host:

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
| `411` | A chunked request body. The broker does not decode one, and refusing is deliberate: forwarding it as an empty body would have the provider answer a request the caller never sent. Send `Content-Length`. |
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

- **No consumer.** No deployed workload declares credential material, on either
  substrate, and there is no sandbox VM and no guest image. The feature has zero
  users; the two workloads the rig stands up are throwaways it creates and
  destroys.
- **Nothing runs the end-to-end check but a person.** The seam is proven (see
  below) by a rig needing root and two VMs of its own, so it is neither a PR
  gate nor part of the runtime rung. A regression in it surfaces when someone
  next runs it by hand, not when it is introduced. Defects of this kind pass
  the whole unit suite and reach hardware.
