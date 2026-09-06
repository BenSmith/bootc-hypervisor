# Manual rigs

Checks that need a real KVM host and cannot run in the normal suites. Nothing
here runs under `just test` or `just test-runtime`; each is invoked by hand on a
host that has the workloadctl RPM installed.

## broker_rig.py — does a guest get a key it never holds, and can two brokers tell each other's callers apart?

Needs root, KVM and the workloadctl RPM installed. Boots **two** throwaway VM
workloads, runs a stub provider on the host, and probes from inside each guest
and from the host as each workload's own uid.

```bash
sudo python3 tests/manual/broker_rig.py
```

**This is a rewrite, not the rig that was here.** The old one probed a host-wide
broker at an advertised endpoint (192.0.2.1:8081) that every guest was told
about, reached through a uid-keyed nft redirect. ADR 007 deleted that whole
shape, so all 18 of its assertions were about a mechanism that no longer exists
and it was deleted with them. Patching only the `workload.toml` it generated
would have been worse than deleting it: `tests/test_manual_rig_configs.py` would
have gone green over a rig that still dialled an address nothing answers, and
the failure would have looked exactly like the thing under test — the specific
decay that gate exists to catch. The old rig is recoverable from git history if
a future reader wants its scaffolding.

**Four claims, on two workloads rather than four.** The old rig needed four
because `broker = true`, `hosts` and the credential name were three independent
config axes and both of its defects lived in their *combinations*. Three of
those axes are gone. The arms now differ in exactly one line — which credential
they name — so a difference in what comes back has one available explanation.

1. A guest reaches a credential-backed host holding a placeholder and never the
   key. Asserted from both ends: the stub reports which `Authorization` arrived,
   and the guest is asked what its whole environment holds. Either half alone is
   satisfied by a broker that attached nothing.
2. A `Host` the broker does not know is refused.
3. A guest dialling `127.129.x.y` directly reaches its own loopback and finds
   nothing — which is the whole of "the guest is never told where the broker
   is", given that the address is derivable by anyone who reads the source.
4. Two workloads get different credentials from two instances. Only this one
   needs the second workload.

**Claim 2 is probed from the host as the workload's uid, not from the guest, and
that is not a shortcut.** A guest cannot construct the request: the inspector
dials the broker only for hosts the policy names with a credential, and
validation refuses a wildcard on such an entry, so every `Host` that can reach a
broker *through a guest* is one the generated config named. The refusal is real
all the same — it is what stands between a compromised inspector and a key
attached to a destination of its choosing — so it is probed where it can be
reached from. Three controls make it mean what it says: the same dial with the
`Host` the config *does* name must return the credential (or the 403 proves only
that nothing was listening), the same dial as **root** must be refused *for its
caller* (or the 403 is consistent with a broker that has stopped checking who is
calling), and the same dial as the **other workload's** uid must be refused too
— both instances are on the same host's loopback, so nothing but the uid check
keeps one workload's caller out of the other's credential. Both refusals are
403, so each assertion matches the broker's sentence rather than the status.

**What the host-side scaffolding costs.** The broker's upstream is
`https://<the Host>` with no override — deliberately, so a policy-matched path
cannot be prefixed on the way out — so the provider has to answer at that name
on 443. The rig writes one `/etc/hosts` line, binds `127.0.0.1:443`, and removes
both at teardown. The stub's certificate is handed to each broker instance
through `SSL_CERT_FILE` in a drop-in rather than installed into the host trust
store, on `policy_rig.py`'s reasoning: the trust decision stays the broker's,
made the way it always is, and the rig leaves no trust anchor behind on a
machine it borrowed. Nothing about the path under test is weakened — the drop-in
adds one environment variable and changes no directive.

**Last green 2026-09-02: 35/35, on a KVM host under enforcing, against the
installed RPM.** It has now found five defects, none of which any unit test
could see. The first two made the brokered path inert for a real guest:

- `_serve_terminated` seeds the upstream pool with the ORIGIN connection it
  opened before the first request was read, keyed by the host. A brokered
  request for that host found the entry, was handed the origin, and `dial` was
  never called — so the request reached the provider carrying the guest's own
  placeholder while the record said a credential had been attached. Fixed by
  giving the broker leg a pool slot of its own.
- The broker's address is `127.129.x.y`, which is inside `wl_internal4`, and
  that drop is keyed on the workload's cgroup and sits ABOVE the skeleton's
  `oif lo accept`. So once the broker WAS dialled, the packet was dropped by
  the rule that exists to stop a guest reaching the LAN — presenting exactly as
  a broker that is down. Fixed by arming the broker's own address as an
  internal exemption for workloads that have one.

The second was predicted in the listener's own refusal text ("a missing SELinux
rule on this dial presents exactly like a broker that is down") and arrived
through nftables instead.

Three more came out of reading what the first two implied:

- **The generated config could not name a provider's auth convention.** ADR 007
  names the profile as `(upstream, credential, auth_header, auth_format)`; the
  render emitted the first two, so every instance ran `x-api-key: {secret}` and
  any provider wanting `Authorization: Bearer` answered 401 on a request the
  inspector had recorded as fully authorised and brokered. The hand-written
  host-wide config could express it and the generated one could not, which made
  the new shape a regression for a whole class of provider. Both keys are now
  optional on `[[vm.network.credential]]`; the two arms differ in exactly this,
  so one run covers the default and an override.
- **Two policy entries for one host rendered an unparseable `broker.toml`.**
  Splitting a host's rules — `/v1/*` for GET, `/v2/*` for POST, one credential
  — is the ordinary way to write §3 and it validates, but it emitted the host's
  table twice, which TOML refuses: the broker exited at start and every
  brokered request 502'd on a config `validate` had just called clean. Both
  arms now deploy that shape deliberately.
- **The origin was dialled for a brokered host and never written to.** The
  connection was opened before the request was read, verified, pooled and
  abandoned — which made the ORIGIN's reachability and certificate a
  prerequisite for a request that goes to loopback, and reported the failure
  against the origin's name. This rig needed a `[[vm.network.internal]]`
  exemption because of it; **it deliberately no longer carries one**, and that
  absence is the only check on hardware that says the origin dial is gone. If
  it comes back, the first probe fails with `internal destination`.

**It also reads two things no probe can show.** The inspector's own record, for
the rung 6 seam: `upstream` is honestly the broker's loopback address on a
brokered request and `credential` names the material that rode along, which is
what makes a loopback upstream legible rather than alarming. And the audit log,
because a denial on the inspector's *new* access — the dial to the broker's port
— is silent by construction: the connect fails, the listener counts a dead
broker, and the guest gets a 502 naming the broker, which is exactly what a
genuinely dead broker produces. A green run of the four claims does not
establish that the grant is present, only that nothing needed it yet.

## self_dial_rig.py — does the wrong-port counter count, and does `diagnose` say so?

Needs root and a host with at least one workload uid; **no KVM and no VM**,
everything happens in a throwaway network namespace. Install the RPM first — it
reads the installed skeleton and imports the installed modules.

```bash
sudo python3 tests/manual/self_dial_rig.py
```

Three things have to hold and only the first has a unit test: the parser reads
the element shape a counted set renders, the kernel increments that element on
the dropped packet, and `diagnose` gets from the host's nft to the printed
line. The second is why this exists — `meta skuid` cannot be exercised without
a process that really owns the uid, so nothing under `just test` can send the
packet, and a counter that never increments looks exactly like a guest that
never self-dialled. The third is the seam, and every part of this rung that
shipped inert shipped inert at a seam.

**The element shape is the trap.** A set carrying `counter` renders its
elements wrapped, `{"elem": {"val": {"concat": [...]}, "counter": {...}}}`,
where an uncounted set renders them bare. `vm_owned_elements` matches the bare
shape and so finds nothing at all in these sets. The rig reads a real
incremented counter through the real reader, which is the only way to know the
wrapped path was taken rather than assumed.

**Two controls carry the rig.** A dial to a *served* port must not be counted —
a self rule that caught those would drop every guest's own inspector traffic,
which is the failure the rule ordering exists to avoid. And a *root* dial to
the same address and port must not be counted: without that one, every other
assertion still passes against a rule that has lost `meta skuid` and is
dropping the address for everyone, host tooling included. Absent and zero are
also held apart — an unarmed element reads as absent, not as zero.

Last green 2026-08-25, 11 assertions, on a bare-metal Fedora 44 host.

## inspect_rig.py — does a guest told nothing land in the inspector?

The rung's headline claim, and the one thing about it that only a real boot can
show. Needs a KVM host with the workloadctl RPM installed; it boots two
throwaway VM workloads and probes them from inside, then purges them.

```bash
sudo python3 tests/manual/inspect_rig.py
sudo python3 tests/manual/inspect_rig.py --quiet   # failures and the tally only
```

`--quiet` is for reading a run back over ssh rather than watching it: a green
run collapses from 57 PASS lines, several carrying a whole JSON document, to
one tally line. Failures are never suppressed — each prints in full, under the
section header naming the phase it was in, and an escaping exception prints
that header too. `tests/test_manual_rig_quiet.py` pins that, because the branch
that matters here only runs on a KVM host and only when something is already
wrong.

**Two guests, differing in one config line.** The `plain` arm is filtered with
no `hosts`, so nothing is allowlisted and every dial to 80/443 is DNAT'd onto
the listener and dropped there — the redirect's own claim, isolated from any
question about what policy then says. The `hosts` arm is the allowed path: a
dial to an allowlisted name is forwarded (cleartext) or spliced (TLS) and comes
back 200. Nothing else in the rig walks the inspector's *upstream* leg, so
without that arm the forward and splice code paths never execute under SELinux
at all. The single-line difference between the arms is what makes a failure
attributable to one half or the other.

**The negative half is the guest's, and it is new.** The plain arm also dials
`192.0.2.1:3128` and asserts nothing answers, then sets `https_proxy` to that
endpoint and asserts a real `curl` through it fails. An operator upgrading a
workload whose image bakes in the old export, or whose custom seed was written
against the old docs, has to get a hard failure rather than a client that
quietly falls back — otherwise both designs are live at once and the
transparent one is not the only path out.

**The second arm changed shape at rung 2.** It was called `proxy` and carried a
real tinyproxy, and its job was the `wl_inspect_cg` exemption: the proxy's
upstream `CONNECT` leg was `tcp dport 443` from the workload's own uid, so
without that element it was redirected into the listener it was dialling past.
Rung 2 deleted the proxy and with it that member of the set. The exemption
check stays — an inspector missing from the set dials into itself, and **no
unit test can see that fail**, because the element resolves a cgroup id at add
time — but it now covers inspectors and responders rather than proxies.

**The record's seam, added at rung 5 T2.** A live guest makes an *allowed*
cleartext request to an allowlisted host with a per-run marker in its path, and
the rig then reads it back through `workloadctl egress` — the same command an
operator would type. Seven assertions: the file exists with the modes and owner
the design claims (`0700` directory, `0600` file, both `_wl-<name>`), the
allowed request is in it, its `id` is the id on the journal line for the same
connection, `--id` selects that connection alone, the plain arm's denial
carries the `reason` that says *which* denial it was, a non-root read is
refused with a sentence rather than a traceback, and an unknown `--reason` is
an error rather than an empty report.

Nothing in `just test` reaches any of that. The writer is unit-tested against a
fake listener and the reader against a fixture directory, and **both stay green
on a host where the file is never created** — a wrong `LogsDirectory=`, a
missing SELinux label, or a denied write swallowed by the handler that must
never let a diagnostic kill a guest request all look identical from there. The
*allowed* request is the one under test on purpose: refusals already reach the
journal, so a record holding only refusals would be a green reading that says
nothing about the path the private sink exists for.

**The staleness seams, added at rung 5 T4/T5/T7.** Three comparisons between a
value a *running* process holds and a value on disk, which is a shape the unit
suite can only test against injected observations. Ten assertions: the listener
reports a policy digest at all, that digest is the digest of the document on
disk, a healthy workload is *not* reported stale, an edited document *is* — and
its remedy names the VM rather than the socket — the edit is then restored and
the report goes quiet again, all four filter-table sets carry the workload's
uid, and the CA fingerprint the minter reports equals a fresh `openssl x509
-fingerprint -sha256` of the file, with an expiry beside it.

The reason none of that is reachable from `just test` is the same reason the
status-file checks exist at all: **every one of these comparisons treats an
unknown as silence**, deliberately, so that a diagnostic never manufactures a
failure out of a missing diagnostic. A digest the listener could not write, a
set name that drifted, an `nft` the CLI's domain may not exec — each produces
exactly what a healthy host produces. A comparison that never runs and a
comparison that always agrees are the same green line, and only a live host
distinguishes them.

The policy edit is destructive and is undone in a `finally`, with the undo
*asserted* rather than assumed. A rig that breaks the product and then dies
leaves the next run measuring the break, and a break that looks like the
feature under test is the worst kind to inherit.

**What only a real boot showed.** Both defects this rig found were ordering
against user creation, and both passed every unit test. The generator called
`getpwnam` for `_wl-<name>` having only just written the sysusers config, so on
a *first* enable the user did not exist, the `KeyError` hit the per-workload
`try/except`, and the workload got **no VM units at all** — the existing test
mocked `getpwnam`, which is precisely what hid it. And the inspect socket had no
`After=workload-<name>-setup.service`, so it raced user creation and usually
won. A mock of the thing that is missing at boot cannot see the failure.

On a host with no IPv6 uplink the rig installs a temporary route to the probe
address over the inspector's dummy link and removes it afterwards; without it
the v6 probes die at the routing lookup, before nftables is consulted, which
looks like a redirect defect and is not.

On a host with no IPv6 uplink the temporary route makes the guest's v6 source
address come off the `workload-proxy` link, which carries every workload's
listener address — so the listener logs a `peer=` that is some *other*
workload's plane. It is an artifact of the rig's own route, not a policy
finding: the guards match on destination, and a host with a real v6 uplink
sources from a global address. Worth recognising rather than re-investigating.

Last green 2026-08-25, **37 assertions**, on a bare-metal Fedora 44 KVM host
under plain **enforcing** with the shipped dontaudit rules in place. That is the
first recorded run of the post-deletion shape: the rig was rewritten in the same
commit that deleted the proxy, so every earlier figure describes a different rig.

Run under **enforcing**, not `semodule -DB`. A permissive or dontaudit-disabled
pass measures the branch that ran, and an earlier denial changes which branch
that is. The history is worth keeping for that reason: an earlier 31-assertion
run under `-DB` is what *found* the two SELinux findings below — both real,
neither visible from `just test` — and a 33-assertion run under enforcing is
what closed them. `workload-<name>-resolve.service` measuring as `wlresolve_t`
rather than `unconfined_service_t` is the whole of what
`security/workload-resolve.cil` was written for.

**One correction the first post-deletion run produced, in the rig itself.** The
`wl_inspect_cg` check used to sit in `guards()`, before any probe, and it failed
there at 33/34 on a host where nothing was wrong. Under rung 1 the member it
watched was the workload's tinyproxy — an ordinary long-running service, up
before the guards ran. The inspector is socket-activated, and both cgroup
elements are armed by the *service*'s `ExecStartPre`, not the socket's, because
an element resolves to a cgroup id at add time and a socket-bound-but-unstarted
service has no cgroup for one to resolve to. So the set is legitimately empty
until the first guest dial. The check moved after `probes()` and got stronger on
the way: it now matches the exact cgroup path per arm, in *both* sets
(`wl_inspect_cg` for the redirect, `wl_egress_cg` for the default-deny), because
the invariant is both-or-neither and a bare count of `>= 1` is satisfied by one
arm while the other dials into itself.

**Status files.** Both producers keep counters and write them into the VM's
runtime directory, and that write is guaranteed never to raise: a failure is a
journal warning and nothing else. So a confined domain with no grant on that
directory produces precisely what a working one produces — green suite, green
rig, no file. `status_files()` therefore looks for the file itself, checks the
stamp is fresh rather than merely present, and dials again to confirm the
counters *move* (a file written once at startup and never again is a producer
whose every later write is failing). **What the first run actually found was worse than that.** The
module carried NO `qemu_var_run_t` rules, so the listener could not read its own
policy document — `Permission denied: /run/workload-vm/<name>/inspect.json` —
exited 1, and the socket unit restart-looped. Every guest dial to 80/443 timed
out. That is a rung-2 regression, not a T6 one: the policy file arrived and the
grant did not, so on an enforcing host the transparent path had never worked.
Loud, at least, unlike the status write. Note that no sibling grant includes
`rename`, which `os.replace` needs — copying `workload-proxy.cil`'s block
verbatim gives a half-grant that reaches the replace and fails there.

**Domains.** `workload-vm-inspect-listener` has a filecon and a
`type_transition` and should be `wlinspect_t`. `workload-vm-resolve` has
neither, so it entrypoints `bin_t` from `init_t` with nothing to retype it and
runs in PID 1's own domain — a process terminating guest-supplied DNS packets,
outside the boundary `wlinspect_t` exists to draw. Measured on the host, it ran as
`unconfined_service_t` — a process parsing guest-supplied DNS wire format,
unconfined for as long as it had existed, with nothing anywhere failing.
`security/workload-resolve.cil` now supplies `wlresolve_t`. On a permissive
host every check in this group passes trivially, so the rig says so out loud
rather than reporting a green it has not earned.

Two things the rig got wrong on its first run, both fixed, both worth knowing
before trusting a result here. It waited seconds for a status tick when
`STATUS_INTERVAL` is 30s, so it kept reading the pre-loop write — zeros,
freshly stamped, identical to a broken counter. And it demanded the status file
be ABSENT after a restart, which fails a correct system: the inspect service is
`PartOf=workload-<name>.service`, so a VM restart restarts the producer, which
comes straight back up and writes a fresh snapshot with no dial needed. The
property that actually matters is that the previous instance's COUNTS cannot
survive, so the check now makes drops non-zero first and then asserts the
post-restart file is absent or all-zero.

**Stale status across a restart.** The runtime directory is
`RuntimeDirectoryPreserve=yes` (so a restart does not yank the qmp and console
sockets out from under the sidecars) and both producers are socket-activated,
so after a restart the file on disk belongs to the previous boot with no
process running to correct it. `written_at` cannot tell that apart from a live
producer idle since the same moment. The arming helpers clear it, and this is
the only check that can see that wiring — it needs a real preserved directory
surviving a real restart. It asserts *before* anything dials the restarted
guest, because one dial recreates the file for an innocent reason and the check
would pass either way.

### Harvesting the missing policy

Do the `semodule -DB` pass *first*, not after several enforcing iterations.
`workload-inspect.cil`'s own header records a rule that was invisible to four
enforcing runs because shipped policy dontaudits it, and whose only symptom was
a systemd error message naming no SELinux concept at all.

```bash
sudo semodule -DB                        # disable dontaudit, rebuild
sudo python3 tests/manual/inspect_rig.py # provoke the denials
sudo semodule -B                         # restore dontaudit when done
```

Read the denials out of `/var/log/audit/audit.log` directly. `ausearch -ts
boot` has been observed reporting zero records on a host whose log plainly
contains hundreds, so the rig itself remembers a byte offset into the file
rather than asking `ausearch` for a time range. An empty result from
`audit_denials()` means "nothing in the audited set" and is not proof the
domain is complete.

The rig's own config decayed, too: it emitted `allow = ["1.1.1.1:53"]`, the
bare-string form rung 2 retired, and died at `enable` with no VM ever booted —
a surface indistinguishable at a glance from the SELinux findings above. Only
the generator's error message told them apart. `tests/test_manual_rig_configs.py`
now parses and validates the TOML every rig generates, so that class of decay
fails in `just test` rather than on a hardware trip.

## input_chain_rig.py — the two rung-1 measurements no unit test can make

Both concern packets crossing a real kernel hook, which is why `just test`
cannot reach either: one asks whether a drop rule stops traffic that has never
been sent, and the other counts what a capture actually holds.

Unlike the other rigs here it needs **no KVM and no VM** — everything happens in
throwaway network namespaces, so it runs anywhere `ip netns` and `tcpdump` do.
It reads the installed skeleton, so install the RPM first.

```bash
sudo python3 tests/manual/input_chain_rig.py
```

**The off-box drop.** The input chain's `iif != lo ... daddr <plane> counter
drop` has two halves. The loopback half is implied by any green `inspect_rig`
run — if the exemption were wrong, no guest dial would reach the listener. The
off-box half is implied by nothing: the unit tests assert the rules carry
`counter`, which is that the keyword is present, not that it ever increments.
The rig sends a packet in over a veth from a peer namespace, which is the only
way to produce `iif != lo` without another machine.

**The capture doubling.** `pcap_output_rule` and `pcap_input_rule` log to the
same nflog group, and a host-local packet crosses both hooks. Measured: 10
packets on the wire, 18 in the file, `pcap_output` 8 + `pcap_input` 10 = 18. So
the loss check has to sum both counters, and the inflation is **2x, not 4x** —
the 4x needs a second leg, which arrives only when the inspector re-originates.

Every packet a socket sent is captured twice; bare ACKs the kernel emits on its
own behalf appear once, because there is no owner for `meta skuid` to match.

Last green 2026-08-25, 12 assertions, on a bare-metal Fedora 44 host.

## splice_rig.py — does a real session survive the splice, and a real request get authorised?

Rung 2's T4a and T4b claims, and the halves of them the unit suite cannot
reach. Needs root and the installed RPM; **no KVM and no VM** — a throwaway
network namespace, a real TLS origin and a real HTTP origin, and the real
listener process started the way the socket unit starts it.

```bash
sudo python3 tests/manual/splice_rig.py
```

**What the unit tests already hold, and what they cannot.** That the parser
reads a name, and that the buffer replayed upstream is byte-identical to the
one read, are unit tests — the second against a hand-built ClientHello. What no
byte comparison can establish is that a *real* client and a *real* server
complete a handshake through the splice. A hello that is subtly re-serialised —
a reordered extension block, a dropped GREASE value, a rebuilt record header —
still reads as "close enough" in a diff and still fails a real handshake.

**The certificate is the honest question.** The rig's client verifies nothing,
so a wrong certificate reaches the assertion instead of being refused before it
can be looked at, and the assertion compares what the client was handed against
the origin's own DER. If anything between the two terminated the session, that
one check fails and every other check in the rig still passes.

**"The upstream saw nobody" is an assertion, not an aside.** The first version
of this rig reported a denied name completing a handshake — an apparent policy
bypass. It was the rig: its own `dup2(fd, 3)` had clobbered the origin's
listening socket, so the parent raced the listener for the guest's connections
and answered them itself. A false pass in that direction is indistinguishable
from a real bypass, so the origin counts its connections and the denied probe
asserts the count did not move.

**Three drop reasons, checked at runtime rather than in the source.** A name on
no list, an allowlisted name that does not resolve (`nx.invalid`), and bytes
that are not TLS each produce their own line. An operator with one bucket for
the three cannot tell a policy decision from a broken resolver from something
speaking a non-TLS protocol at the TLS port, which is the tunnelling signature.

**The cleartext plane, from the origin's side.** The unit tests drive it over a
socketpair they own, so they read the bytes this process wrote. What they
cannot do is have an *origin* report what arrived — and that is where two of
T4b's claims live: the head reaching the origin is the one we composed (our
framing, our `Host`, hop-by-hop headers gone) rather than the guest's forwarded
on, and the refused request reached nobody at all. Two names are sent down
**one** connection, because a per-connection decision would send the second
request to the first one's upstream and nothing outside would look wrong.

**One control.** A listener whose policy document is missing must fail its
start rather than fall back to an empty allowlist: an empty `hosts` is a legal
configuration, so the fallback could not tell "the operator allowed nothing"
from "the file was not there".

It writes `/run/workload-vm/wlspl/inspect.json` and refuses to start if that
path already exists, since it would be a real workload's policy. Teardown
removes the namespace and the directory.

Last green 2026-08-25, 24 assertions, on a bare-metal Fedora 44 host against
the installed RPM.

Verified by breaking the splice on purpose — replaying the buffer without its
record header — which fails the four handshake assertions and leaves the other
eleven green.

## policy_rig.py — does rung 4 enforce what it claims, against the installed listener?

Rung 4's T1, T3, tiers 4–5, T6, T7 and T9, and the halves of them the unit
suite cannot reach. Needs root and the installed RPM; **no KVM and no VM** — a
throwaway network namespace, one real TLS origin answering to six names, and
the real listener process started the way the socket unit starts it.

```bash
sudo python3 tests/manual/policy_rig.py
```

**Why it exists when every figure below has a unit test.** The unit suite
proves the *decision*; it drives the request over a socket pair it owns. What
it cannot do is show that the decision is reached by the process systemd
starts, from the document on disk, with a real TLS stack on both sides — the
same gap rung 2 and rung 3 each found the hard way.

**One listener, two dispositions, told apart by whose key ends the session.**
`tls = "inspect"` with a `[[vm.network.splice]]` entry produces two different
outcomes on one process, and the only honest way to say which happened is the
certificate the client is holding when the handshake finishes: the spliced host
hands back the origin's own DER, the inspected host a leaf this workload's CA
signed. Either one alone proves nothing — a listener that spliced everything
and a listener that terminated everything each pass half of the pair.

**"Reached nobody" is measured in requests, not connections.** §6 establishes
the upstream leg *before* the guest's handshake completes, precisely so nothing
sniffs the guest to decide what to say upstream — so by the time a request can
be refused on policy, the origin has already been dialled. The first version of
this rig asserted the connection count and reported that design as a leak. What
must never arrive is the *request*, and that is what every refusal here checks.

**Both halves of the h2 bypass.** A host in `[[vm.network.http2]]` that speaks
h2 relays its preface to an origin that selected h2. The same host sent an
HTTP/1.1 request is refused — without that check the key would mean "exempt
from policy" rather than "speaks h2", reachable by writing different first
bytes. And a *second* host is listed whose origin answers `http/1.1` anyway:
an ALPN offer binds nobody, and a server that speaks only HTTP/1.1 completes
the handshake selecting nothing, with no alert of any kind.

**The four split counters, read off a file a real process wrote.**
`tests/test_vm_inspect_diagnose.py` pins each key string against the listener's
own constant, so a rename cannot rot them. What no unit test can say is whether
anything ever *increments* them: a counter that is declared, exported, pinned
and never written reads 0, and 0 is a legal value every test passes. These are
the same figures after the refusals above actually happened, plus the
reconciliation `sum(drop_reasons) == dispositions.dropped`.

**The counter key is not the log line**, and assuming it was got this rig
wrong twice. The log interpolates the server name inside the reason — `host
does not match the server name plain.wlpol.test (allowlisted)` — so the
counter's key is not a substring of it. Matching the log on the allowlisted key
never fires; matching it on the shorter key matches *both* halves, which made
the sibling assertion pass vacuously on a listener that had merged them. The
split is asserted where it is authoritative, in the status document.

**The trust store is the rig's, and the trust decision is still the
listener's.** Every upstream leg is verified fully against the host's anchors
with no configuration key to weaken it — deliberately, since such a key would
turn the inspector into an attacker with a friendly name. So the rig points
`SSL_CERT_FILE` at a file naming its own origin alone. Without it every
terminated host answers 502 `upstream certificate unverified` and every policy
assertion silently measures that instead of policy, which is how the first
run read.

It writes `/run/workload-vm/wlpol/inspect.json` and this workload's CA under
`/var/lib/workloads/wlpol/`, and refuses to start if either exists. The six
test names resolve through `/etc/netns/wlpol/hosts`, which `ip netns exec`
binds over `/etc/hosts` inside the namespace alone — editing the host's own
would leave six entries pointing at a listener that is gone. Teardown removes
all of it.

Last green 2026-08-27, 42 assertions, four consecutive runs on a bare-metal
Fedora 44 host under enforcing, against the installed RPM.

Verified by emptying each rung-4 list in the policy document in turn, on a
throwaway copy so the product is never touched. Emptying `splice` fails 2 of
the 42 (the origin's own certificate stops coming back); emptying `http2` fails
8, including the HTTP/1.1 request that the entry is what refuses — without the
entry it is relayed and answered 200; emptying `policy` fails 8. Each break
lands on the assertions written for it and leaves the rest green.

## clock_rig.py — what a vCPU pause does to a guest's clock, and whether a wrong clock costs the guest its egress

```bash
sudo python3 tests/manual/clock_rig.py       # --keep leaves the guest up
```

Needs root, `/dev/kvm`, the workloadctl RPM and the same
`/var/lib/broker-rig/base.qcow2` the other VM rigs use. Boots **one** throwaway
filtered VM workload **with its egress inspector on**, measures its clock
across a QMP `stop`/`cont`, tries both forms of the guest agent's
`guest-set-time`, and then drives a real HTTPS request from a guest whose clock
is deliberately wrong. Ten minutes end to end, most of it the 120-second pause
and cloud-init's first boot.

**Why it exists.** Rung 3 mints 30-day leaves for the guest to validate, which
puts the guest's clock on the critical path for all of its traffic. Drift is a
non-issue — about 10 ppm, four orders of magnitude inside a leaf's window — but
a *pause* is not: the guest loses the pause exactly and never gets it back, and
the 1-hour `notBefore` backdate covers roughly 1,200 years of drift and exactly
one hour of pause. Past that, every freshly-minted leaf has a `notBefore` in the
guest's future and validation fails on every request while `diagnose` reports a
healthy VM.

**One of the two paths that reaches it is ours.** `workloadctl backup
--consistency crash` issues QMP `stop`, copies the qcow2, and `cont`s in a
`finally`, resyncing nothing — so the guest is left behind by the copy duration,
bounded by disk size and storage speed rather than by any check. The rig pauses
over the same socket in the same order, so it is measuring that operation and
not an analogue of it.

**The guest is filtered on purpose.** An `egress = "open"` guest would resync
over NTP and measure nothing. The rig records that NTP is dead first, because
that premise is invisible from the host: `chronyd` stays `active` while
`chronyc tracking` reports stratum 0 and a 1970 reference time.

**Offsets are reported as intervals, not numbers.** The guest's clock is read
somewhere inside the `workloadctl exec` round-trip, so the reading is bracketed
by two host reads and the interval's *width* is that latency. The upper bound is
the stable one; the lower tracks the round-trip.

**Last green 2026-09-02: 19/19, on a TSC-clocksource KVM host under enforcing,
against the installed RPM.** The same 19/19 was recorded on 2026-08-27; the
re-run was against a later build, on a host also carrying live production
workloads, with clean teardown and nothing else disturbed. Rungs since then
deliberately deferred this rig — they touch nothing it covers — so the re-run
exists to close one residual doubt: a later rung deleted an `ExecStopPost` from
*every* VM unit, including ones with no broker, which is the generic VM unit
path this rig exercises.

**The `ptp_kvm` arm needs a host this rig does not control**, and that is the
one thing to check before reading a result. `ptp_kvm` answers only where the
**host's** clocksource is the TSC; on `hpet` or `acpi_pm` the module refuses to
load in every guest and measurements 3, 3b and 3c skip, saying so. An earlier
run on such a host reached 8/9 and could say nothing about the guest-side
remedy. Two homelab hosts qualify; check the candidate rather than assuming.

**What the guest-side arm settled, once it could run at all.** `/dev/ptp_kvm`
appears, chrony selects it as a refclock (`#* PHC0`, ~874 ns) with
`makestep 1 -1`, and **the guest repairs a 120-second pause by itself in 24
seconds**. Measurement 3c then turns the remedy off, and the rest of the rig
measures the guest that a custom `user_data_file` produces — one with no
`ptp_kvm` wiring — rather than contriving a second workload for it.

**What it settled about the pause itself.** The step equals the pause to 25 ms
(119.984 s against 120.008 s), the guest survives it, and **nothing puts it
back**: still 119.3 s behind after resume with the guest-side remedy off.
`guest-set-time` with **no argument fails** — it reads the guest's RTC
and returns `hwclock: select() to /dev/rtc0 to wait for clock tick timed out`,
which corrects an earlier note recording it as not returning at all. The
**explicit-nanoseconds form works**, taking the guest from −120.9 s to +0.6 s,
inside the measurement's own bracket. That is the remedy rung 3 adopts.

The no-argument form is a *finding*, not a defect in the rig, and is recorded
as an observation rather than a failure so a future QEMU or image that makes it
work shows up as a change here. It has been stable across both full runs.

**Measurement 7 closes the loop, and it needed T5 to exist.** Everything above
measures a clock; 6 measures what the clock was on the critical path *of*. It
pushes the guest **two hours** back — past the `notBefore` backdate, so a stale
clock cannot validate a fresh leaf by accident — and then asks it for a name it
has never asked for, which is the only kind that reaches the minter: a cache hit
runs no clock check, so re-dialling a warm name would pass while proving
nothing. The request should succeed, because the mint path repairs the guest
before signing.

Two corroborating assertions matter as much as that one. The guest's offset must
come back, and `clock_resyncs` in `inspect-status.json` must move — without
both, the same green is produced by a backdate quietly widened to cover two
hours. A third reads `clock_unavailable`: a guest with no `qemu-guest-agent` is
a supported configuration in which this whole remedy is *inert*, and every other
line on this rig still passes in that state.

This arm needs the host to have real internet, unlike the rest of the rig — it
dials two names on the workload's allowlist.

---

## rung5_rig.py — do rung 5's reporting surfaces tell the truth about a live guest?

Rung 5's T6 (`workloadctl rules`), T8 (`doctor`'s egress section) and T9 (the
exporter's inspector series). Needs root, `/dev/kvm` and the installed RPM —
`workloadctl` and `workload-exporter` are invoked by name, off PATH and out of
`/usr/libexec`, exactly as an operator gets them. Two throwaway VMs: one
filtered, one with `egress = "open"`.

```bash
sudo python3 tests/manual/rung5_rig.py
sudo python3 tests/manual/rung5_rig.py --quiet   # failures and the tally only
```

**Why it exists when every figure has a unit test.** All three surfaces are
tested against documents written by hand. What no unit test can reach is
whether the document those readers open is the one a *live listener* wrote, at
the path it really writes it to, with the permissions it really writes it with,
and whether the numbers in it move when a guest actually dials something. Three
claims only a host settles:

- **`rules` reports origin `disk`.** Off a host every test takes the `config`
  fall-back, because there is no `/run/workload-vm/<name>/inspect.json` to
  prefer — so the preferred branch, and the 0640 root-owned read that goes with
  it, had never executed against a file the listener wrote.
- **`doctor` and the exporter agree.** Decision 9 says one producer, and the
  unit suite proves the two renderers agree about a hand-written document.
  Agreeing about a live one is a different claim: both must have opened the
  same file, through their own code paths, and come back with the same numbers.
- **The counters move.** A reader stuck at zero passes every assertion written
  against a document full of zeros. The rig drives an allowed request and a
  refused one and insists the figures changed.

**The policy is two entries over one host, and both state both keys.** Two
entries are the point — they union, neither overrides the other, and `rules`
has to print both against the one name, which is the §3 composition rule the
report exists to make visible. Both entries state `methods` *and* `paths`
because `validate` refuses overlapping entries that omit one: an omitted key
means ANY, so the omitting entry silently permits everything its sibling was
narrowed to forbid. Written the natural way — one entry for methods, one for
paths — the rig fails at `enable` with no VM ever booted, which looks nothing
like the thing under test. `tests/test_manual_rig_configs.py` caught exactly
that before this file first reached a host.

**Admission is read off two status codes, not asserted directly.** Nothing
serves `api.example.com`, so the governed probes end 502 at the dial rather
than as policy decisions — and that is the signal, not a flaw: reaching the
upstream at all is what proves the host was admitted, while the unlisted probe
never gets that far and is refused at the allowlist with a 403. Whether a
permitted request is permitted and a forbidden one forbidden is `policy_rig`'s
question, against a stub origin built to answer it.

**The unlisted probe uses `--resolve`, not DNS.** The synthesising resolver
answers only for names the lists carry, so an unlisted name never resolves and
never becomes a connection — the drop would be the *resolver's*, and the
inspector's `not allowlisted` counter would stay at zero. Every egress port is
redirected, so any address reaches the listener and the SNI decides.

### Reading a failure

Every probe's result is recorded, pass or fail. The first version of this rig
ignored `curl`'s result, so a guest that had not finished booting produced no
traffic, no socket activation and no status document — and the rig reported
that as eight failures about `doctor` and the exporter, none of which named the
cause. If the traffic line says a probe returned nothing, read no further down:
everything below it is measuring an inspector that was never dialled.

---

## container_egress_rig.py — does the container substrate actually filter?

The first rig here that needs **no KVM**. Everything the VM rigs prove about
the egress path was proven on a guest; this asks the same questions of a
container, where the traffic is re-originated by pasta as the workload's own
uid rather than by passt on a guest's behalf. Needs root, podman and the
installed RPM. Throwaway container workloads, all prefixed `ceg-`. **104/104 on a bare-metal
Fedora 44 host under enforcing, 2026-09-06**, against an RPM built from the
branch under review — up from 78/78 after two PR-shaped reviews added the pod,
ordering and resolver sections below.

```bash
sudo python3 tests/manual/container_egress_rig.py
sudo CEG_LAN_HOST=192.0.2.10 python3 tests/manual/container_egress_rig.py
sudo python3 tests/manual/container_egress_rig.py --keep   # leave them running
```

**The ladder is walked on one workload, not built three times.** Rung 1 (no
`[network]` egress key), rung 2 (`hosts` only, spliced, no CA), rung 3 (a
`[[network.policy]]` entry, refused until `ca_delivery` is stated, then
terminating) are three states of one file with a `workloadctl recreate` between
them. Three separately-enabled workloads would each prove their own end state
and say nothing about the *transition*, which is where a silently-gained CA
requirement would hide. It also settles the apply question by exercising it:
`recreate`, never `restart` — `restart` regenerates no units, and the rung-3
transition adds a bind mount and five environment variables to the podman argv.

**Both redirected planes, and the cleartext one first.** A rig that checks 443
and stops leaves plaintext HTTP unfiltered in a workload every report calls
filtered. The assertion on port 80 is not that the request succeeded but that
the record carries a `method` and a `path` — that the *Host header* was read,
not merely that the dial landed somewhere.

**The re-dial check is a stopwatch, not a return code.** A missing cgroup
exemption in either table does not error: one loops the inspector into itself
and the other filters its upstream leg like the workload's own, and both
present as a request that eventually times out. So the rig asserts the elements
are present *and* that a request which used them finished well inside a
wall-clock budget.

**`[[network.internal]]` is probed in both directions.** Testing only the
entry-present case would pass against an inspector with no internal-destination
guard at all — which is the guard that stops an allowlisted *public* name from
being pointed at your LAN. Without `CEG_LAN_HOST`, and if that host does not
answer on port 80 from the machine running the rig, this section **skips**: a
probe against an unreachable target fails identically to a working drop.

**One reporting surface is asserted to REFUSE; two more are measured, not
asserted.** `rules` is VM-only pending the container document renderer and its
refusal names the trigger, which is the shape a VM-only surface should have.
`drift` and `pcap` are merely *unrouted*, which is not the same as declining —
whatever they do, an operator meets it, so the rig records it rather than
guessing. `diagnose` used to be in that list and no longer is: G7 routed it, so
a filtered container now gets an inspector line like a VM's.

### Cross-workload inspector reachability — now scored

**This was the one thing the rig measured and did not score. The decision it
was waiting on has landed, and it was "close it", so the probe asserts.**

Two layers now stop it, and the rig requires both to hold. `workload_filter`
drops a non-root packet aimed at a live inspector address that is not the
sender's own (`@wl_inspect_live`), and the listener refuses a caller whose uid
is not the workload's own — root included — through `lib/peer_identity.py`,
which reads the kernel's socket table because `SO_PEERCRED` is AF_UNIX-only
and says nothing about a TCP peer. A `REACHED` line is a regression in one of
those two.

The original note is kept below because the shape of the hole is worth
remembering: `nftables/workload-proxy.nft` argues
that a uid with no element in the redirect maps cannot reach another workload's
inspector, because its packet leaves untranslated and meets the default-deny
drop in `workload_filter` — but that drop is itself guarded on `@wl_filtered`
membership, which an unfiltered workload of *either* substrate is also not in.
So the argument does not close for a container, and reading the rule suggests
it does not close for an `egress = "open"` VM either.

The rig dials the filtered workload's listener from the unfiltered container,
on the listener's real ports rather than through a redirect. Reaching it was
never only a reachability problem: the dials landed in the *victim's* egress
records, so a workload's own record of what it sent described traffic it never
sent. Of the three remedies weighed — a peer-credential check in the listener,
an input-chain rule covering co-resident uids, or an accepted and documented
boundary — the first two were both taken, and the boundary was not accepted.

### The three rows that "needed another host", and two of them never did

These sat unrun for a fortnight each, deferred on the grounds that this host
was the wrong one. Re-reading what each actually needed, two were a fixture
rather than a machine, and the rig now stands both up and tears them down.

**IPv6** needed a v6 destination the kernel will *route*, not an uplink. A
ULA on the far side of a veth is one: the packet is built, the routing lookup
succeeds, and it arrives at the nftables hook under test. An uplink would have
added an ISP to the measurement rather than removing a doubt from it. The
discriminating probe is the *denied* one — a second name at the **same
address** that is not in `hosts`, so a refusal for it can only have come from
the inspector reading the name.

**A moved `[[network.allow]]` address** needed two stub origins with different
bodies and one line in `/etc/hosts`. Which origin answered is the whole
question, and one origin moved would make "the pin held" and "the rotation
never took" the same reading.

**`ca_delivery = "env"` against an embedded root store** did need something
absent, and what was absent was an *image*, so it is a pull. **The obvious
example is the wrong one**: Node looks like the canonical "ignores
`SSL_CERT_FILE`" client, and `NODE_EXTRA_CA_CERTS` is one of the five variables
workloadctl delivers — so Node trusts the CA and the row would pass having
measured nothing. Go reads `SSL_CERT_FILE` too. A JVM reads none of the five;
its anchors are `cacerts` inside the image.

**The origins live in a network namespace behind a veth, and that is
load-bearing.** The first version put them on a dummy link, which made every
address *local* — and `workload-filter.nft` accepts a filtered uid's traffic
unconditionally when `oif lo`, because loopback is the workload's control plane
and not egress. A local origin is reached whether or not any element authorises
it, so the rotation row would have passed its dial and proved nothing.

**Two product defects came out of the first hardware pass**, both of them
about legibility rather than enforcement, which is why every functional
assertion around them was green:

1. **No surface named a stale `allow` address.** The pinning worked in both
   directions, and after a rotation `diagnose`, `doctor` and `validate` between
   them named neither the stale address nor the entry that pinned it — while
   `egress` had nothing at all, because the inspector is not in this path and
   never sees the connection. The whole visible symptom was a dial that used to
   work. `diagnose` now carries an `allow_drift` check, on both substrates.
2. **The refused-handshake message named a VM-only remedy.** A client that
   rejects the minted leaf was told "a guest provisioned before this workload
   had a CA does not trust it and must be re-seeded" — right for a stale VM
   seed, and actively misleading for a container whose trust store is baked
   into the image, which has no seed to revisit and no CA route to repair. The
   JDK arm hit exactly that: all five CA variables delivered and readable, and
   the JVM refused the leaf anyway. The sentence now names both shapes and the
   remedy each needs, `[[network.splice]]` included.

Two rig bugs came out of the same pass, and both are the class this file keeps
warning about. `fd00:ceg::` is not a valid address — `g` is not a hexadecimal
digit — and the row reported it as "nothing could bind", three layers from the
cause. And the rotation row passed for the wrong reason: `/etc/hosts` had been
rewritten and the caches flushed, but the *container* was still being answered
with the old address, so the probe reached the old origin and read as a pass.
It was measuring a DNS cache and reporting it as the arm-time pin. Both are now
preconditions the rig asserts before the row it guards.

### Pod mode, and the ordering that no steady-state row can see

**Added 2026-09-06, after two PR-shaped reviews found the hole these rows now
guard.** The egress arming used to live on the umbrella
(`workload-<name>.service`), which looked right — `[network]` is
workload-level, one uid per workload, and the umbrella is the unit that
represents "this workload is up". But the umbrella is `After=` its members, so
systemd started every container *first* and ran the arming afterwards. For the
whole of member startup the workload had no `wl_filtered` element, no DNAT and
no listener: it ran completely unfiltered, image pull included, and then became
filtered mid-flight.

**Why 78/78 was green over it.** Not "the rigs are single-mode" — this rig has
deployed a filtered bridge workload since P1-9. It is that every row measured
**steady state**: enable, recreate, sleep, probe. By the time anything is
probed, a workload that armed late and one that armed on time are identical.
The bug lives entirely in the window before the first probe.

So `check_head_unit_ordering` asserts the *ordering*, not the presence of a
string — a containment check passes for any unit ordered after the members,
which is exactly how the original P1-14 test passed over this. Five of its six
rows read systemd's parsed state rather than the generated file, because only
the host can say what the manager actually loaded, and the two differ after an
RPM upgrade without a regenerate — the state the `%post` scriptlet warns about.

**The load-bearing row is the one about the umbrella, not the head unit.**
`the umbrella really is ordered AFTER its members` pins the *premise*. Without
it, "the arming is on the head unit" is a preference; with it, the old
placement is provably a hole. It reads 2/2 on a live host.

The sixth row is an observation rather than a configuration reading: monotonic
start timestamps for the head unit and each member. Head-first by 0.09 s in
bridge mode and 0.33 s in pod mode.

**Pod mode had never run on a host at all.** `check_bridge_mode` covered one
multi-container topology and nothing covered the other, so pod mode reached a
release exercised by unit tests alone — on the substrate where the ordering
hole lived. `ceg-pod` carries **two** members deliberately: with one member
there is less window, and the claim is that the arming precedes *all* of them.
The second member is also probed against a denied host on its own, because it
shares the pod's netns and therefore the redirect; if only the first were
filtered, every other assertion here would still pass with half the pod
unfiltered.

### The default deny takes DNS, and it is a fact about the host

`check_container_resolver` (S10). **Measured 2026-09-06; before that it was a
reading of the rule and nothing more.** A triggered container's uid enters
`wl_filtered` and meets the last rule in the output chain. The port-53 accept
in `workload-filter.nft` is scoped to `wl_egress_cg` — the **inspector's**
cgroup, which a container is never in — so a container's queries survive only
through `oif lo`. A loopback stub (127.0.0.53) resolves fine; a LAN resolver is
a workload-uid socket to a routable address on port 53 that no rule accepts,
and the container then resolves **nothing**, including the hostnames its own
`hosts` allowlist names.

**Every host this rig has ever run on uses the resolved stub**, this one
included. That is why the whole hardware history passed through the `oif lo`
accept without anyone choosing it — the green measured the branch that ran.

**The fixture is a routable resolver, not another host.** What the row needs is
a port-53 destination the kernel will route off loopback, and the far side of
the existing veth is one. The namespace is load-bearing for the reason it is
everywhere else here: an address on a dummy link is *local*, `oif lo` accepts a
filtered uid's traffic to it unconditionally, and the row would pass having
measured the exemption instead of the drop.

**Both protocols.** The drop carries no protocol qualifier and the accept above
it matches `th dport`, which is TCP and UDP alike — but real DNS is UDP first,
and a TCP-only probe leaves the protocol resolvers actually use unmeasured.

**A drop is not always a timeout, and the difference turned out to be the best
evidence in the section.** An nftables `drop` in the *output* chain rejects a
**local** sender synchronously, so the blocked UDP query fails at `send()` with
`EPERM` rather than waiting — measured, not predicted. (The green run reported
it as the raw `ERR 1`; the `DROPPED-EPERM` label was added afterwards and
changes the printed detail only, never a verdict.) That is the filter's own
signature: an absent reply is also what a dead responder looks like, `EPERM` is
not. The TCP half does time out, and the control row is what makes *that*
readable. Connection-refused means the packet *arrived* and nothing was
listening — a dead fixture reporting itself as a working filter. So a refusal
counts as `reached`, and an unfiltered uid must reach the responder before any
other row is scored. Without that control, a responder that never came up
satisfies every assertion in the section.

The remedy is asserted too, not just the break: an `[[network.allow]]` entry
for the resolver **on port 53 specifically** — the element is
(uid, address, port), and an entry written without the port arms nothing that
matches, which is why `diagnose`'s message spells the TOML out rather than
saying "add an allow entry".

### What it still does not measure

**A global-scope IPv6 destination.** The redirect map keys on `tcp dport`
alone, so translation is scope-blind and the ULA result carries — but that is a
reading of `workload-proxy.nft`, not a measurement, and it is the one claim
here still worth a v6-capable host.

## uid_attribution_rig.py — which uid does a container's egress actually leave as?

Needs root and the workloadctl RPM; no KVM and no base image, so this is the
cheapest rig here to run. Deploys three throwaway single-container workloads
that differ only in `[container] user`, and counts one SYN from each against
three competing nftables selectors.

```bash
sudo python3 tests/manual/uid_attribution_rig.py          # host mode
sudo python3 tests/manual/uid_attribution_rig.py pasta    # the shipped path
```

### What it answers

P0-1 from the container egress-parity build spec: does `[network] mode =
"host"` keep uid attribution? Every rule in `nftables/workload-filter.nft`
selects on the single workload uid, so the whole design rests on a container's
packets carrying it. Measured 2026-09-05 on a KVM host under enforcing:

|                    | image default | `user = "0"` | `user = "1000"` |
| ------------------ | ------------- | ------------ | --------------- |
| `mode = "pasta"`   | workload uid  | workload uid | workload uid    |
| `mode = "host"`    | workload uid  | **subuid**   | **subuid**      |

The cause is that `[security] userns` defaults to `keep-id`: exactly one
in-container uid maps to the workload uid, and every other one — including
in-container root — maps into the workload's 65536-wide subuid window. Pasta
hides this entirely, because it re-originates the container's traffic as a host
socket that it owns. Host mode has no such indirection: the container's sockets
*are* host sockets, and two arms of three leave as subuids no shipped rule
matches. That is why `validate_container_network()` refuses `mode = "host"`
combined with any egress key — the alternative was filtering whichever
containers happened to run as the keep-id uid while reporting the workload as
filtered.

Both arms also confirm the other half of P0-1: the host's own traffic is never
captured. Root and an ordinary user matched no workload selector on any arm,
even with the network namespace shared.

### Why counters rather than an end-to-end dial

Nothing is armed for a host-mode workload, so there is nothing to dial through.
Three counters competing for one packet at the output hook measure the
primitive itself and cannot be confounded by whether an inspector is up,
whether a route exists, or whether anything is listening. The destination is
unroutable on purpose (TEST-NET-3), so every probe is a single SYN and the only
variable is which rule claimed it.

### Four ways this rig lied before it told the truth

Each read as a product defect first, and the code is shaped by all four. A rig
that lies is worse than no rig: its failure looks exactly like the thing under
test, which is the same decay `tests/test_manual_rig_configs.py` exists to
catch one level up.

1. **`nft reset counters table` resets named counters only**, not the anonymous
   per-rule ones used here. Every row inherited the previous row's count, and
   one probe that sent *no packet at all* was dressed up as a match. Now deltas.
2. **busybox `su` is not GNU `su`** and refused to drop privileges with `must
   be suid to work properly`. The "non-root" probe would have measured root and
   read as a clean falsification of the hypothesis it existed to test. It now
   proves the uid changed before its verdict counts.
3. **keep-id injects the host username into the container's `/etc/passwd`**, so
   `id` inside prints `uid=10002(_wl-<name>)` — which looks exactly like an
   `exec` that escaped to the host. It had not; that *is* the container, and
   the surprise was the finding rather than a bug.
4. **Retransmits cross probe boundaries.** An unroutable destination leaves
   every probe retransmitting on a doubling backoff, and under pasta those are
   re-originated by a long-lived host process owned by the workload uid — so
   they land in the next probe's window and attribute the host's own `curl` to
   the workload. A settle-and-hope window fits *inside* a backoff gap; each
   probe now gets its own destination port and a freshly built table, which
   makes the contamination unmatchable rather than unlikely.

### What it deliberately does not measure

**IPv6** — `container_egress_rig.py` now covers the v6 redirect on a ULA
fixture, but this rig measures the uid *selector*, which is family-blind
(`meta skuid` reads neither address nor family), so there is nothing here a v6
arm would add. **Whether the
DNAT redirect would capture host traffic in host mode** — it cannot, because
nothing arms a redirect for a host-mode workload; the rig measures the uid
selector, which is the part the design depends on. **`userns = "host"`**, where
in-container root maps to the workload uid directly and the mapping question
does not arise; the refusal covers it regardless, which is deliberate — a
`[network]`-level rule that changed meaning based on a `[security]` key would
be the kind of coupling nobody remembers.

---

## deployed_snapshot_rig.py — do the workloads nobody opted in still get the same units?

The one guarantee an opt-in phase owes above all others: a workload that did
not opt in gets **exactly** what it got before. `tests/test_generator_snapshot.py`
asserts that against the bundles committed to this repo — the smaller set, and
the one whose shapes were chosen by whoever wrote the feature. A `[network]`
shape that no bundle contains but a live host does is precisely what a
bundle-derived snapshot is structurally unable to cover.

So this rig reads the other set: `/etc/workloads.d` on real hosts. It pulls
every deployed config, renders each one through the generator from two git
revisions (`git archive`, so neither the worktree nor the current branch is
touched), and diffs every emitted unit and sysusers file byte-for-byte.

```
./deployed_snapshot_rig.py --before <rev> [--after HEAD] --self-check <ssh-target>...
```

It needs ssh and passwordless sudo on each host, and nothing else — no root
here, no KVM, no podman. The generator is a pure function from config to unit
text, which is what makes this cheap enough to run against every host on every
phase.

### What it answers

- **Byte-identical, per deployed config.** Rows are tagged `no trigger` or
  `opted in via <key>`; an opted-in workload is *supposed* to change, so the
  tag is reported and never asserted.
- **Does the `mode = "host"` refusal take a live workload down?** The refusal
  fails closed — the generator emits no units, so a workload pairing host mode
  with an egress key stops running rather than running unfiltered. That is the
  right direction and still an outage, and "no shipped bundle uses that
  combination" was only ever a claim about this repository.
- **Can the differ see a difference at all?** `--self-check` perturbs the
  "after" generator, asserts every row goes red, then reverts and asserts they
  all go green again. A rig that compares nothing prints the same clean sweep
  as one that works.

### Three ways it lied before it told the truth

1. **The render root is in the output.** Each render gets a fresh `mkdtemp`
   whose path lands in the emitted `ExecStart=/usr/bin/systemd-sysusers ...`
   line, so *every* unit differed for a reason having nothing to do with the
   generator. First run: 2/18 identical, all 16 "failures" spurious.
2. **A disabled workload renders nothing, and nothing equals nothing.** Two
   deployed workloads carry no `.enabled` marker, so the generator skipped them
   and they compared equal having emitted zero units — passing rows that tested
   precisely nothing (the same shape as a permission that is granted but never exercised).
   The marker is now forced and a zero-unit render is a hard error.
3. **The self-check's mutation ignored indentation.** Pasted at column 0 it was
   an `IndentationError`, the generator emitted nothing for any config, and the
   rig reported 18 broken workloads instead of one broken rig. The probe is now
   re-indented to its anchor's own column, and a mutation that fails to apply
   is itself a FAIL rather than a silent no-op.

### What it deliberately does not measure

Whether the deployed units on disk match what the generator *would* now write —
that is `workloadctl drift`, and it is a different question. This rig compares
two generators against one config, not one generator against one host.
