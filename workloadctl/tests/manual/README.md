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
