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
  `socat`, OVMF, `tinyproxy`, `passt`, `nft`)
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

Last green 2026-08-22, 11 assertions, on a bare-metal Fedora 44 host.

## inspect_rig.py — does a guest with no proxy variables land in the inspector?

Rung 1's headline claim, and the one thing about it that only a real boot can
show. Needs a KVM host with the workloadctl RPM installed; it boots two
throwaway VM workloads and probes them from inside, then purges them.

```bash
sudo python3 tests/manual/inspect_rig.py
```

**Two guests, differing in one config line.** The `plain` arm is filtered with
no `hosts`, so the guest has no proxy variables at all and its dial to 80/443
is DNAT'd onto the listener — the rung's actual claim. The `proxy` arm has
`hosts`, so tinyproxy runs and its upstream `CONNECT` leg is `tcp dport 443`
from the same uid; without the `wl_inspect_cg` exemption that leg is redirected
into the inspector — which, from rung 2, terminates it: the proxy's connection
to its own upstream is answered by the listener it was dialling past, and every
proxied HTTPS request fails. (When the rig was first green the listener only
logged, so the same failure presented as a hang.) **That
exemption has no unit test that can see it fail** — the element resolves a
cgroup id at add time, so nothing static can tell an armed one from a missing
one. The single-line difference between the arms is what makes a failure
attributable to one half or the other.

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

Last green 2026-08-22, 17 assertions, on a bare-metal Fedora 44 KVM host —
re-run after rung 1's two closing items landed, so it covers the tree as it
stands and not only the state the two ordering defects were fixed in.

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

Last green 2026-08-22, 12 assertions, on a bare-metal Fedora 44 host.

## splice_rig.py — does a real TLS session survive the splice?

Rung 2's T4a claim, and the half of it the unit suite cannot reach. Needs root
and the installed RPM; **no KVM and no VM** — a throwaway network namespace, a
real TLS origin, and the real listener process started the way the socket unit
starts it.

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

**Two controls.** The cleartext plane must still only log — tinyproxy filters
port 80 by name today, and a listener that quietly started terminating it would
break that with no test failing. And a listener whose policy document is
missing must fail its start rather than fall back to an empty allowlist: an
empty `hosts` is a legal configuration, so the fallback could not tell "the
operator allowed nothing" from "the file was not there".

It writes `/run/workload-vm/wlspl/inspect.json` and refuses to start if that
path already exists, since it would be a real workload's policy. Teardown
removes the namespace and the directory.

**Not yet run on a host.** All 15 assertions are green as of 2026-08-22, but
under `unshare -rn` in a dev container rather than through the `ip netns`
wrapper this file's `main()` uses — that container cannot create a named
namespace. So the probes, the listener, the origin and the policy path are all
proven; the outer setup and teardown are not. Run it on a KVM host and replace
this paragraph with the usual line.

Verified by breaking the splice on purpose — replaying the buffer without its
record header — which fails the four handshake assertions and leaves the other
eleven green.
