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

**Not green against this shape yet.** The rig was rewritten in the same commit
that deleted the proxy, so the last recorded run describes a different rig and
saying otherwise would be the worst of the options: a "last green" line that
survives the change it did not cover.

What the recorded runs said, kept because the *reasoning* still applies. On
2026-08-25 this rig was green at **33 assertions** on a bare-metal Fedora 44 KVM
host, and two runs were worth keeping apart. The earlier one, at 31 assertions,
ran with `semodule -DB` in effect and is what *found* the two SELinux findings
below; both were real, and neither was visible from `just test`. The
33-assertion run is the one that closed them, and it ran under plain
**enforcing** with shipped dontaudit rules in place — which is the harder
result: a permissive or dontaudit-disabled pass measures the branch that ran,
and an earlier denial changes which branch that is. The two added assertions
were the domain checks, and `workload-<name>-resolve.service` measuring as
`wlresolve_t` rather than `unconfined_service_t` is the whole of what
`security/workload-resolve.cil` was written for.

Re-run under **enforcing**, not `-DB`, for that reason. The rewrite moved the
allowed path onto an arm whose traffic used to be exempted before the inspector
saw it, so the forward and splice legs now execute in a configuration no
recorded run has measured — which is exactly the case where a permissive pass
would report a green that means nothing.

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
