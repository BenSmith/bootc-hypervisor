# Manual rigs

Checks that need a real KVM host and cannot run in the normal suites. Nothing
here runs under `just test` or `just test-runtime`; each is invoked by hand on a
host that has the workloadctl RPM installed.

## broker_rig.py — the VM-to-credential-broker path

Boots four throwaway VM workloads, runs a broker and a stub upstream on the
host, and probes the broker from inside each guest. 18 assertions, ~4 minutes
after the first run (which downloads a Fedora Cloud image).

It used to be here because the broker lived in a separate repository, so the rig
could not be satisfied by anything in this tree alone. That is no longer true —
the broker ships in the workloadctl RPM. What keeps it out of `tests/cli_surface/`
now is only what keeps everything else in this directory out: it needs root and
boots four VMs of its own, so promoting it into the runtime rung is harness work
rather than a dependency question.

### What it needs

- a KVM host, root, and the VM toolchain (`qemu-system-x86_64`, `qemu-img`,
  `socat`, OVMF, `passt`, `nft`) — no `tinyproxy`, which rung 2 retired
- the workloadctl RPM installed: the rig runs the *installed* broker at
  `/usr/libexec/workloadctl/agent-broker`, so a green run says the package is
  right. `just rpm-install` refreshes it from the checkout.
- outbound HTTPS on first run, for the cloud image

It creates `/var/lib/broker-rig/` for the image, credentials and logs, and
generates a throwaway certificate for the stub which the broker trusts through
`SSL_CERT_FILE` — deliberately not through the host's trust store, so a
borrowed machine gets nothing installed into it.

```bash
sudo python3 tests/manual/broker_rig.py            # --keep leaves it all up
```

Teardown purges the four workloads, removes the config directories it wrote,
and stops both services. `--keep` skips all of that for debugging; the next run
refuses to start if either port is still held.

### What it proves

Four guests, each differing from the first in exactly one line of config, so a
failure is attributable:

| arm | config | expectation |
|---|---|---|
| a | proxy + broker | 200, and the credential is a's |
| b | proxy + broker | 200, and the credential is b's |
| c | broker, no proxy | 200, and the credential is c's |
| d | proxy, no broker | connection refused |

a versus b is identity: two guests dial the same advertised literal and get
different credentials, because the uid owning the socket differs. a versus d is
reachability, which fails independently — d has no element in the redirect map,
so nothing translates its packet and nothing is listening where it lands. A
403 for d would be a *failure*: it would mean d connected and was identified as
a stranger, which is a different property than the one being claimed.

There is also a probe on `a` with `NO_PROXY` cleared and the proxy forced,
which must be refused by the proxy with a 403. That one is a regression test:
before the advertised address was added to `NO_PROXY`, every client honouring
proxy variables sent its broker request to the proxy and got exactly that 403 —
a refusal indistinguishable from the broker rejecting an unauthorised caller.

### Reading a failure

The assertions carry their own interpretation, including which wrong answers
are meaningful. Two worth knowing in advance:

- **502 from the broker** means the guest reached it and was identified; the
  upstream leg is what failed. That is a rig problem (the stub, its
  certificate), not a routing or identity problem.
- **403 from the broker** means the caller was not resolved to a configured
  sandbox. Check that the workload users exist and that the broker is not
  running in a user namespace, which makes every caller read as the overflow
  uid.

Host-side logs are in `/var/lib/broker-rig/{broker,stub}.log`.

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
```

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

**What it settled, 2026-08-26, 8/9 assertions.** The step equals the pause to
37 ms. `guest-set-time` with **no argument fails** — it reads the guest's RTC
and returns `hwclock: select() to /dev/rtc0 to wait for clock tick timed out`,
which corrects an earlier note recording it as not returning at all. The
**explicit-nanoseconds form works**, taking the guest from −120.9 s to +0.6 s,
inside the measurement's own bracket. That is the remedy rung 3 adopts.

The one FAIL is the no-argument form and is the *finding*, not a defect in the
rig: it is asserted rather than skipped so that a future QEMU or image making it
work shows up as a rig that started passing.

**Measurement 6 closes the loop, and it needed T5 to exist.** Everything above
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
