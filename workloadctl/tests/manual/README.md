# Manual rigs

Checks that need a real KVM host and cannot run in the normal suites. Nothing
here runs under `just test` or `just test-runtime`; each is invoked by hand on a
host that has the workloadctl RPM installed.

## Writing a row here

These rigs exist because unit gates do not see the seam. They have blind spots
of their own, and every rule below was paid for by a defect that shipped past a
green rig. Read this before adding a row; the rest of the file is what each rig
found.

**Probe the window, not the settled state.** Every row in
`container_egress_rig` followed one shape — enable, recreate, sleep, probe —
and that shape is blind to a control that arms *too late*. The egress arming
sat on the umbrella unit, which is `After=` its members, so every container
started unfiltered and the workload became filtered mid-flight; by the time
anything was probed, that is indistinguishable from correct. The class is
general and it is most of what these rigs guard: a filter, a policy load, a
seccomp profile, a cgroup move can all be right and late. If a row sleeps
before it measures, ask what it would miss.

**Assert the ordering, not the presence of a string.** A containment check
(*"the arming appears in this unit"*) passes for any unit ordered after the
members, which is exactly how the test covering the above stayed green. Read
systemd's **parsed** state — `systemctl show <unit> -p ExecStartPre` and
friends — not the generated file: only the host says what the manager actually
loaded, and the two differ after an RPM upgrade without a regenerate, which is
the state the `%post` scriptlet warns about. Where an observation is available
rather than a configuration reading, prefer it;
`ExecMainStartTimestampMonotonic` is comparable across units.

**Pin the premise as its own row.** "The arming is on the head unit" only
matters because the umbrella runs late. Without a row asserting *that*, the
remedy is a preference, and a future change could quietly make it pointless.
The premise row is usually the one worth writing first.

**A row can assert the defect and pass on it.** The `rules` row here pinned
`"no inspected egress"` — the sentence an *uninspected* workload gets — so for
weeks it was green over precisely the bug a later review found. When a product
message changes, the row that pinned it must be **re-derived from what the
message should now say**, not edited until it goes green again. A row that only
ever had to pass is a row that has stopped measuring.

**Every "needs another host" deferral deserves re-reading.** Four rows here sat
deferred on that basis and three needed a *fixture*: a veth, an `/etc/hosts`
line, a routable address in a namespace. Ask what property the row actually
needs before asking for a machine.

**And check the fixture cannot satisfy the property by accident.** An origin on
a dummy link is *local*, and `oif lo` accepts a filtered uid's traffic
unconditionally — so a row measuring a drop would have measured the loopback
exemption and passed. Put fixtures behind the veth. Where a row asserts
something is blocked, add a **control row** proving an unblocked caller reaches
the same fixture: without it, a responder that never started satisfies every
assertion in the section.

**A drop is not always a timeout.** An output-chain nft `drop` rejects a
*local* sender synchronously, so a blocked UDP send fails with `EPERM` rather
than hanging. Prefer that reading where it is available — an absent reply is
also what a dead fixture looks like; `EPERM` is not. Conversely
connection-*refused* means the packet arrived and nothing was listening, which
is a broken fixture reporting itself as a working filter, and must never count
as blocked.

**Iterate under enforcing, never permissive**, and assert on `audit.log`
directly rather than on functional success — a silent denial leaves the feature
working and the counters reconciling. `ausearch -ts boot` is unreliable on at
least one host here; grep the log.

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
store: the trust decision stays the broker's, made the way it always is, and the rig leaves no trust anchor behind on a
machine it borrowed. Nothing about the path under test is weakened — the drop-in
adds one environment variable and changes no directive.

**The guard rows read the manager's parsed `ExecStart=`, not a file.** The
broker takes everything as flags on the generated unit now: there is no
`broker.toml`, no `ExecStartPre` and no runtime directory, and the row that
used to `cat` the config as the workload uid and expect a refusal has become
four rows on `systemctl show -p ExecStart` — the line names the workload's own
uid and address; it carries the placeholder (the positive half, so the next
row measures something); it carries no secret (it is on a world-readable unit,
so this has to be true rather than arranged); and `ExecStartPre` is empty and
the runtime directory absent.

**Last green 2026-09-21, all 41 rows, on a KVM host under enforcing, against
the installed RPM** (broker-flags: the first run in which the broker started
from the generator's `ExecStart=` flags, with the four guard rows above; both
arms' keys arrived at the stub, `x-api-key` for the default convention and
`Authorization: Bearer` for the overridden one, and no denial in the audit
log). Before that 2026-09-21 at 35 rows against inspector-flags (the
inspector's broker endpoint as a `--broker` flag the generator computes; this
is the rig that dials it), and 2026-09-20 against inspector-decouple, where
the endpoint was a value the launcher derived.
It has now found five defects, none of which any unit test
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
  table twice, which TOML refused: the broker exited at start and every
  brokered request 502'd on a config `validate` had just called clean. Both
  arms now deploy that shape deliberately. (The file is gone — the broker
  takes `--host` flags — but the broker refuses a repeated host for a reason
  of its own, so the shape still has to collapse on the host and the arms
  still deploy it.)
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
where an uncounted set renders them bare. `owned_elements` matches the bare
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

Last green 2026-08-25, all rows, on a bare-metal Fedora 44 host.

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

Last green 2026-09-21, **all 57 rows**, on a bare-metal Fedora 44 KVM host
under plain **enforcing**, against the installed RPM at the inspector-flags
merge -- the first run in which the listener started from the generator's
`ExecStart=` flags rather than a bare name it derived the rest from. Before that
2026-08-25, all rows, same host and posture with the shipped dontaudit rules in
place: the first recorded run of the post-deletion shape, since the rig was
rewritten in the same commit that deleted the proxy and every earlier figure
describes a different rig.

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

**Domains.** `customs-inspect` has a filecon and a
`type_transition` and should be `wlinspect_t`. The responder (then
`workload-vm-resolve`, now customs' `customs-resolve`) had
neither, so it entrypointed `bin_t` from `init_t` with nothing to retype it and
ran in PID 1's own domain — a process terminating guest-supplied DNS packets,
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

Last green 2026-08-25, all rows, on a bare-metal Fedora 44 host.

## clock_rig.py — what a vCPU pause does to a guest's clock, and whether a wrong clock costs the guest its egress

```bash
sudo python3 tests/manual/clock_rig.py       # --keep leaves the guest up
```

Needs root, `/dev/kvm`, the workloadctl RPM and the same
`/var/lib/broker-rig/base.qcow2` the other VM rigs use. Boots **one** throwaway
filtered VM workload **with its egress inspector on**, measures its clock
across a QMP `stop`/`cont`, tries both forms of the guest agent's
`guest-set-time`, drives a real HTTPS request from a guest whose clock is
deliberately wrong, and then skews it again with nothing dialling and waits for
the clock keeper. Twelve minutes end to end, most of it the 120-second pause,
cloud-init's first boot, and two waits on a one-minute timer.

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

**Last green 2026-09-21, 29/29 on a TSC-clocksource KVM host and 26/26 on
an hpet one (3b skipped, as designed), both under enforcing, against the
installed RPM** (inspector-flags: the inspector is started from an
`ExecStart=` that hands it `--name --policy --state-dir --status --record
--broker`, all computed by the generator; the journal shows it terminating
and forwarding for the guest from that line, 7 and 8 measure as below. The
first TSC run went 28/29: the keeper's domain row read `init_t` off
systemd's pre-exec child, which systemd 259 names `(workload-vm-clock)` in
/proc for ~10 ms before execve -- the rig's catch now skips it, header.)
Previous: 2026-09-20, 29/29 (TSC) and 26/26 (hpet)
(no-clock-hook: the inspector's per-mint clock resync is
gone, and 7 now measures the failure it used to prevent -- `certificate is
not yet valid` on a fresh leaf with the keeper held off, `mints +2` while the
inspector reports healthy, the clock untouched, `diagnose` red with the
offset -- before 8 releases the keeper and the same leaf validates on a cache
hit with `diagnose` green. A `semodule -DB` harvest on both hosts: `wlclock_t`
attempted exactly the three denials `security/workload-clock.cil` declines to
grant, and `wlinspect_t`, minting and terminating for a real guest, attempted
none of the three agent-socket grants that were removed from it.)
Before that: 2026-09-20, 27/27 (TSC) and 24/24 (hpet) under enforcing
(clock-keeper: measurement 8 arrived -- the keeper's tick caught live in
`wlclock_t`; the first run of that row failed a working domain by reading
the journal's `_SELINUX_CONTEXT`, above). Before that, 2026-09-20, TSC host
under enforcing (inspector-decouple). Green on 2026-09-02 and
2026-08-27; the re-run was against a later build, on a host also carrying live
production workloads, with clean teardown and nothing else disturbed. Rungs since then
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

**Measurement 7 closes the loop by measuring the failure.** Everything above
measures a clock; 7 measures what the clock is on the critical path *of*. With
the clock keeper's timer stopped (and recorded as stopped), it pushes the guest
**two hours** back — past the `notBefore` backdate, so a stale clock cannot
validate a fresh leaf by accident — and asks it for a name it has never asked
for, so the leaf it is handed is minted now. The handshake must **fail** with
`certificate is not yet valid`. Four corroborations say why it failed: the
inspector's `mints` moved (it signed the leaf and has no idea), the `mint`
block carries no clock or remedy figure (the minter used to run a per-mint
resync and count it; the counters left with the check, and a key reappearing
is the seam coming back), the guest is **still** two hours out afterwards
(nothing on the mint path touched it), and `workloadctl diagnose --json` fails
its `vm_guest_clock` line naming the offset — the operator's one view of a
guest the keeper cannot see or has not yet reached.

This arm needs the host to have real internet, unlike the rest of the rig — it
dials two names on the workload's allowlist.

**Measurement 8 is the remedy.** `workload-<name>-clock.timer` runs
`libexec/workload-vm-clock` once a minute for every VM, inspector or not, in
its own `wlclock_t` domain. The rig starts the timer on the guest 7 left
skewed and polls the offset for the keeper's period plus its accuracy. Then it
dials the name 7 failed on **again**: the same cached leaf must validate now,
on a cache **hit** (`hits` moves, `mints` does not), because the clock is what
changed and not the certificate. The tick is caught running with `wlclock_t`
in its label, the keeper's journal line appears exactly once, and `diagnose`
goes green on the same line it was red on.

**The domain is read off the live process, not the journal, and the first
run of this row failed a working domain by doing the latter.** A oneshot
leaves no `MainPID` to ask, so the rig scans `/proc` at 20 Hz for the tick and
reads its `attr/current` before it exits. The obvious shortcut — journald's
`_SELINUX_CONTEXT` on the keeper's stdout line — reads `init_t` on every
service that transitions on exec, because for `_TRANSPORT=stdout` that field is
the stream socket's peer label, captured when systemd's pre-exec child
connected it; `_COMM` and `_EXE` on the same line are post-exec, which is what
makes it convincing. Measured 2026-09-20.

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
permitted request is permitted and a forbidden one forbidden is customs'
rigs' question, against a stub origin built to answer it.

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
installed RPM. Throwaway container workloads, all prefixed `ceg-`. **Last green all 153 rows on a
bare-metal Fedora 44 host under enforcing, 2026-09-21** (broker-flags: the
container substrate's broker instance started from the generator's
`ExecStart=` flags and the brokered request reached the provider carrying the
sealed key; the LAN row run with `CEG_LAN_HOST` set), earlier the same day
against inspector-flags (the first run in which the container substrate's
inspector started from the generator's flag line), before that
2026-09-20 (inspector-decouple; one row skipped for want of `CEG_LAN_HOST`),
and before that 2026-09-06
against an RPM built from the branch under review, with the `rules`/`drift`/`pcap` reporting rows
re-run after they were converted from measured gaps to assertions.

It has grown in four waves: two PR-shaped reviews added the pod, ordering and
resolver sections; then the credential broker arm; then the record reader,
rotation and purge; then the three reporting verbs above. That lineage is
worth keeping. A row COUNT is not, which is why one is no longer written
here: it went stale on every wave, it says nothing about what is covered —
twenty rows over one surface and twenty over twenty are the same number — and
a pinned total quietly invites keeping the number up rather than keeping the
coverage honest. The count is in the run's own output, where it belongs.

Use `--only=<section>,<section>` to iterate one arm. A full pass is ~40
minutes, and three of the six defects below were found by re-running a single
section in three.

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
is not the workload's own — root included — through `customs.peer_identity`,
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

**The credential broker arm (P2) is 19 rows, and the last one is a real
request.** A container holding only a placeholder makes a request that reaches
the provider carrying the sealed key. The three refusal rows — another
workload's uid, root, and the container being unable to name `127.129.x.y` at
all — sit behind a control row proving the broker serves its OWN inspector,
without which all three are satisfied by a broker that is dead. That is not
hypothetical: on the first hardware run they were, because **nothing started
the broker**. The unit was generated, ordered ahead of the right unit, given
its `IPAddressAllow=` and its `wl_internal_ok4` element, and pulled in by
nothing. `Before=` orders a unit; it does not start one. Forty-five unit rows
passed with it in place, because each reads the broker unit's own text and the
missing half lived in a different unit.

**The record's readers (P3) are three arms, and every negative row has a
positive one in front of it.** Everything this rig read before them came back
through a single invocation — `egress <name> --json -n 0`, as root, over the
live file — so a thousand lines of reader had one path through it. The rest is
now scored: the flat and grouped renderers, `--host`, `--since`/`--until`, the
closed `--reason` vocabulary (an unknown value must be an *error naming the
set*, because an empty report is what a workload that never hit that refusal
looks like), `-n -1` refused as not a count, the non-root branch reached with
`setpriv`, and the no-record-file branch. **A reader that returned an empty
list unconditionally would score full marks on any set of negative
assertions** — it answers "no records", "nothing matched" and "nothing in that
window" identically and plausibly. So each is paired with a row over a record
whose host, path and time the section itself caused. Same shape as the dead
broker, one surface over.

**Rotation is the only moment the record file is created by the listener
rather than by systemd**, so it is the only moment the owner, the mode and the
SELinux label come from a different actor — and a write that fails there does
not raise. `RequestLog` warns once and never again, by design, so a broken
rotation is a record that silently stops on a host where every unit is active
and every counter still moves. The arm forces a rotation, **makes a request
before asserting anything about the new file** (the listener sets a flag in the
handler and reopens on the next write, so an immediate assertion measures the
flag), then checks owner, mode, label, and that `egress` reads *across* the two
generations rather than only the live one.

**`disable --purge` is asserted, not left to cleanup.** The rig ran bare
`disable` and purged in teardown, where nothing reads the result — so the code
that removes the record tree had never executed for a container. What it
prevents is not tidiness: the next workload given that uid inherits a
`LogsDirectory=` owned by a user that no longer exists, systemd refuses to set
it up, and the inspector fails `240/LOGS_DIRECTORY` while the workload itself
starts fine — hanging on 80 and 443 and nothing else, with the explanation in a
different unit's journal. The pre-purge rows are the control: without them,
"the directory is gone" is satisfied by one that was never created.

**P3-0 is measured and deliberately not scored.** It asks what the listener
sees as the *near* end of a container connection, because a pod- or
bridge-mode workload is N containers under one uid and the record names the
workload. There is no correct answer to pin: a single address means no
attribution is available and the disclosure is the deliverable; a per-container
address means a second reading with two members is worth taking. Nothing is
added to the record until that reading exists — a field that is constant in
every topology is worse than no field, because it reads as attribution.

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
