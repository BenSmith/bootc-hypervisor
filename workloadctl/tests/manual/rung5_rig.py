#!/usr/bin/python3
"""
rung5_rig.py — do rung 5's three reporting surfaces tell the truth about a
real, running, filtered guest?

WHAT NEEDS A HOST HERE, and it is not the arithmetic. Every figure and every
sentence these three surfaces produce is unit-tested against a document written
by hand. What no unit test can reach is the seam: whether the document those
readers open is the one a LIVE LISTENER wrote, at the path it really writes it
to, with the permissions it really writes it with, and whether the numbers in it
move when a guest actually dials something. [[unit-gates-dont-see-the-seam]] is
this tree's recurring finding, and rungs 3 and 4 each landed four seam defects
behind a fully green tier 1.

Concretely, the three things only a host answers:

  * `rules` reports origin "disk". Off a host every test takes the "config"
    fall-back, because there is no /run/workload-vm/<name>/inspect.json to
    prefer — so the whole preferred branch, and the 0640 root-owned read that
    goes with it, has never executed against a file the listener wrote.
  * `doctor` and `workload-exporter` agree. Decision 9 says one producer, and
    the unit test proves the two renderers agree about a HAND-WRITTEN document.
    Agreeing about a live one is a different claim: it needs both to have read
    the same file, at the same moment, through their own code paths.
  * the counters MOVE. A reader that always returns zeros passes every
    assertion written against a document full of zeros. This rig makes a guest
    dial an allowed host and a denied one and then insists the figures changed
    — which is [[counter-with-no-writer-reads-zero]] inverted, and the reason
    the allowed/denied split is driven rather than assumed.

WHY ITS OWN GUEST rather than reusing inspect_rig's. The policy this rig needs
is not the policy that rig needs: `rules` is only interesting where a
[[vm.network.policy]] entry governs a host, because §3's composition rule (a
governed host is governed by THOSE ENTRIES ALONE, with `hosts` not consulted for
it) is the one thing the report exists to make visible. inspect_rig's arms
differ by one line on purpose and adding a policy entry to either would spoil
that.

Not in `just test` and not in the runtime rung: it needs root, /dev/kvm, and the
INSTALLED RPM — `workloadctl` and `workload-exporter` are invoked by name, off
PATH and out of /usr/libexec, exactly as an operator gets them. A rig that
imported lib/ would prove the checkout works and say nothing about the package.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

BASE_IMAGE = Path("/var/lib/broker-rig/base.qcow2")
DNS_ALLOW = "1.1.1.1:53"

NAME = "wlr5-probe"
# A second, unfiltered VM. Its whole job is the negative: an unfiltered
# workload must get NO inspector series and NO Egress section, and "no series"
# is only a finding if some other workload in the same run got some.
PLAIN = "wlr5-plain"

# The three hosts the policy names, and each is a different arm of §3:
#   ALLOWED   is in `hosts` and in no policy entry -- allowlisted, any method,
#             any path.
#   GOVERNED  is in `hosts` AND has two policy entries. The report must say the
#             allowlist is not consulted for it and print BOTH entries, because
#             they union and neither overrides the other.
#   UNLISTED  is on no list at all -- refused, and the sentence has to name the
#             two lists that admit rather than "no list names this host".
ALLOWED = "example.com"
GOVERNED = "api.example.com"
UNLISTED = "unlisted.invalid"

# A routable-looking literal the unlisted probe is pointed at with --resolve.
# Never dialled for real: every egress port is redirected to the inspector
# before the packet leaves the host, so what is on the far side is irrelevant
# and using a literal keeps DNS out of the probe entirely.
PROBE_ADDR = "93.184.216.34"

# The listener's STATUS_INTERVAL. The status file is written once before the
# accept loop and then on this cadence, so a check that dials and reads a few
# seconds later reads the PRE-LOOP write: zeros, freshly stamped, and
# indistinguishable from a producer whose counting is broken. inspect_rig
# learned this the hard way and the note is repeated rather than cited because
# a rig that has to be read alongside another rig to be safe is not safe.
STATUS_INTERVAL = 30.0
STATUS_SETTLE = STATUS_INTERVAL + 6

EXPORTER = "/usr/libexec/workloadctl/workload-exporter"


@dataclass(frozen=True)
class Arm:
    name: str
    filtered: bool


# The ARMS/`toml_for(arm)` shape every other rig here uses, and adopted for a
# reason beyond consistency: tests/test_manual_rig_configs.py discovers rigs by
# their `toml_for` and validates what they generate, and it calls it with an arm.
# Written with a two-argument toml_for this file was DISCOVERED and then errored
# in the gate -- which is the good failure. A rig that quietly did not fit the
# selector would have been skipped silently, which is
# [[gates-have-gaps-in-their-own-shape]] and how the gate written for one rig
# ended up not covering it.
ARMS = (Arm(NAME, True), Arm(PLAIN, False))

results = []

QUIET = False
_section = None
_section_shown = False


def say(msg):
    global _section, _section_shown
    if msg.startswith("=="):
        _section, _section_shown = msg, False
    if not QUIET:
        print(msg, flush=True)


def _show_section():
    global _section_shown
    if QUIET and _section and not _section_shown:
        print(_section, flush=True)
        _section_shown = True


def record(label, ok, detail):
    results.append((label, ok, detail))
    if not ok:
        _show_section()
    if ok and QUIET:
        return
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {detail}", flush=True)


def run(argv, check=True, timeout=120):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{argv!r} rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def cli(*args, check=False, timeout=180):
    return run(["workloadctl", *args], check=check, timeout=timeout)


def guest(script, name=NAME, timeout=90):
    return subprocess.run(
        ["workloadctl", "exec", name, "--", "bash", "-lc", script],
        capture_output=True, text=True, timeout=timeout)


def preflight():
    if Path("/proc/self/uid_map").read_text().split()[1] != "0":
        sys.exit("run as root")
    for p in (BASE_IMAGE, Path(EXPORTER)):
        if not p.exists():
            sys.exit(f"missing {p}")
    if not Path("/dev/kvm").exists():
        sys.exit("no /dev/kvm")


def toml_for(arm):
    name, filtered = arm.name, arm.filtered
    lines = [
        f"# {name} — generated by rung5_rig.py. Throwaway; safe to purge.",
        "[workload]",
        f'name = "{name}"',
        "enabled = false",
        "",
        "[vm]",
        f'local_image = "{BASE_IMAGE}"',
        "vcpus = 1",
        'memory = "768M"',
        'user = "workload"',
        "rollback_keep = 1",
        "",
        "[vm.network]",
    ]
    if not filtered:
        lines.append('egress = "open"')
        return "\n".join(lines) + "\n"
    # EVERY [vm.network] SCALAR FIRST. A scalar written below a
    # [[vm.network.policy]] table belongs to that table, not to the section --
    # [[toml-subtable-ordering-footgun]], and the schema doc's own ordering
    # invites it. The failure is silent: the config parses, and the workload
    # gets a policy entry with a stray key and no `hosts` at all.
    lines += [
        'egress = "filtered"',
        f'hosts = ["{ALLOWED}", "{GOVERNED}"]',
        "",
        "[[vm.network.allow]]",
        f'address = "{DNS_ALLOW}"',
        'reason  = "the guest needs a resolver to reach at all"',
        "",
        # Two entries over one host, which is the whole point: they UNION and
        # neither overrides the other, so `rules` has to print both against the
        # one name. One entry would be indistinguishable from a report that
        # simply echoed the file.
        #
        # BOTH KEYS ON BOTH ENTRIES, and not for symmetry: `validate` refuses
        # overlapping entries that omit one, because an omitted key means ANY
        # and so the omitting entry silently permits everything its sibling was
        # narrowed to forbid. Written the natural way -- one entry for methods,
        # one for paths -- this rig fails at `enable` with no VM ever booted,
        # which looks nothing like the thing under test.
        # [[manual-rigs-decay-against-schema-changes]] is that failure, and
        # this file was caught by running validate_workload_config() over its
        # own generated TOML before it ever reached a host.
        "[[vm.network.policy]]",
        f'host    = "{GOVERNED}"',
        'methods = ["GET"]',
        'paths   = ["/v1/*"]',
        "",
        "[[vm.network.policy]]",
        f'host    = "{GOVERNED}"',
        'methods = ["POST"]',
        'paths   = ["/v2/*"]',
    ]
    return "\n".join(lines) + "\n"


def deploy():
    say("== deploying ==")
    for arm in ARMS:
        d = Path("/etc/workloads.d") / arm.name
        d.mkdir(parents=True, exist_ok=True)
        (d / "workload.toml").write_text(toml_for(arm))
    for arm in ARMS:
        say(f"  enabling {arm.name} ...")
        p = cli("enable", arm.name, timeout=900)
        if p.returncode != 0:
            sys.exit(f"enable {arm.name} failed:\n{p.stdout}\n{p.stderr}")
    # `enable` returns when the units are STARTED, which is minutes before the
    # guest answers anything: first boot runs cloud-init. Driving traffic into
    # a guest that is still booting is silent -- every request fails, the
    # socket-activated listener never runs, no status document is ever written,
    # and the whole T8/T9 half of this rig fails eight assertions later with
    # "status_present=False". Which is what it did on its first hardware run.
    say("  waiting for the guest to answer ssh (first boot: cloud-init) ...")
    deadline = time.time() + 600
    while time.time() < deadline:
        r = guest("echo UP", timeout=60)
        if r.returncode == 0 and "UP" in r.stdout:
            say(f"  {NAME} up")
            return
        time.sleep(10)
    subprocess.run(["journalctl", "-u", f"workload-{NAME}.service",
                    "-n", "40", "--no-pager"])
    sys.exit(f"{NAME} never became reachable")


def drive_traffic():
    """Make the counters move, in both directions, and SAY whether they did.

    Both arms are driven rather than one: a reader stuck at zero passes every
    assertion made against zeros, and a reader that counts only allows looks
    identical to a working one until something is denied. The dispositions and
    the drop reasons are separate maps in the document and separate rows in the
    table, so a rig that only ever allowed would leave half of both untested.

    EVERY REQUEST IS RECORDED, pass or fail. The first version of this function
    ignored curl's result entirely, so a guest that had not finished booting
    produced no traffic, no socket activation and no status document -- and the
    rig reported that as eight failures about `doctor` and the exporter, none of
    which named the actual cause. A step whose failure is invisible until
    something downstream misreports it is the rig bug that looks exactly like a
    product bug, which this tree has now hit four times.
    """
    say("== driving traffic ==")
    codes = {}
    for label, script in (
        # Allowlisted, no policy entry: relayed to a real origin, and it moves
        # `terminated`. The only probe with a live upstream.
        ("allowed", f"https://{ALLOWED}/"),
        # Governed by both policy entries. NOTHING SERVES THIS NAME -- it is
        # allowlisted and governed on paper and has no upstream at all -- so
        # both governed probes end 502 at the dial, not as policy decisions.
        # That is not a defect in the probe: reaching the upstream at all is
        # what proves the host was ADMITTED, and the contrast with the unlisted
        # probe's 403 below is the assertion. Whether a permitted request is
        # permitted and a forbidden one forbidden is policy_rig's question, on
        # a stub origin built to answer it; this rig owns the reporting.
        ("governed-permitted", f"https://{GOVERNED}/v1/ping"),
        ("governed-denied", f"https://{GOVERNED}/v9/ping"),
        # On no list at all. --resolve rather than DNS: the synthesising
        # resolver answers only for names the lists carry, so an unlisted name
        # never resolves and never becomes a connection -- the drop would be
        # the RESOLVER's, not the inspector's, and the inspector's
        # "not allowlisted" counter would stay at zero. Every egress port is
        # redirected, so any address reaches the listener and the SNI decides.
        ("unlisted", f"--resolve {UNLISTED}:443:{PROBE_ADDR} https://{UNLISTED}/"),
    ):
        p = guest(f"curl -sS -o /dev/null -m 25 -w '%{{http_code}}' {script} "
                  f"2>&1 | tail -1")
        code = p.stdout.strip()[-3:] if p.stdout.strip() else ""
        codes[label] = code
        say(f"  {label}: rc={p.returncode} {p.stdout.strip()[:60]}")
    # Not "every request succeeded" -- three of the four are refused one way or
    # another. What has to be true is that the guest ran curl at all, which is
    # what separates "nothing was blocked" from "nothing was attempted".
    record("the guest was reachable and ran every probe",
           all(codes.values()),
           ", ".join(f"{k}={v or 'no output'}" for k, v in codes.items()))
    record("an allowlisted host with a live upstream is relayed",
           codes.get("allowed") == "200",
           f"{ALLOWED} -> {codes.get('allowed')}")
    # ADMISSION, read off the difference between the two refusals. A governed
    # host is dialled and fails at the upstream (502); a host on no list never
    # gets that far and is refused at the allowlist (403). One code each way is
    # the whole of what separates "admitted, then broke" from "never admitted",
    # and it is the distinction an operator brings `rules` to answer.
    record("a GOVERNED host is admitted — it reaches the dial and fails there, "
           "while an UNLISTED one is refused before it",
           codes.get("governed-permitted") == "502"
           and codes.get("unlisted") == "403",
           f"governed={codes.get('governed-permitted')} "
           f"unlisted={codes.get('unlisted')}")
    say(f"  waiting {STATUS_SETTLE:.0f}s for the status write ...")
    time.sleep(STATUS_SETTLE)


# --- T6: rules ---------------------------------------------------------------

def rules_checks():
    say("== T6: rules, against the document the listener wrote ==")

    p = cli("rules", NAME, ALLOWED)
    out = p.stdout
    record("rules reads the document on DISK, not a re-render of the TOML",
           "/run/workload-vm/" in out and "has not started this boot" not in out,
           # The branch no off-host test can take: every unit test falls back to
           # "config" because there is no /run file to prefer.
           next((line.strip() for line in out.splitlines()
                 if "document" in line), out[:120]))
    record("an allowlisted host is admitted and terminated",
           "matched by" in out and "terminated and parsed" in out,
           out.strip().splitlines()[-1][:120] if out.strip() else "(no output)")

    p = cli("rules", NAME, GOVERNED)
    out = p.stdout
    record("a governed host says the allowlist is NOT consulted",
           "allowlist is NOT consulted" in out,
           "; ".join(l.strip() for l in out.splitlines() if "policy" in l)[:160])
    record("BOTH governing entries are printed, because they union",
           out.count("methods:") >= 2,
           f"{out.count('methods:')} entry line(s)")
    wrote = all(t in out for t in ("GET", "/v1/*", "POST", "/v2/*"))
    record("the entries are the ones the TOML wrote, both of them",
           wrote,
           "GET /v1/* POST /v2/* all present" if wrote else out[:200])

    p = cli("rules", NAME, UNLISTED)
    out = p.stdout
    record("an unlisted host is refused",
           "refused" in out,
           next((l.strip() for l in out.splitlines() if "refused" in l),
                out[:120]))
    record("the refusal names the two lists that admit",
           "`hosts`" in out and "policy entry" in out,
           "names hosts and policy" if "`hosts`" in out else out[:160])

    p = cli("rules", NAME)
    out = p.stdout
    record("the enumeration walks the document's literal names",
           ALLOWED in out and GOVERNED in out,
           out.splitlines()[0][:120] if out else "(no output)")

    p = cli("rules", NAME, "--json")
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        doc = {}
    record("--json reports origin disk and the real path",
           doc.get("origin") == "disk"
           and str(doc.get("path", "")).startswith("/run/workload-vm/"),
           f"origin={doc.get('origin')} path={doc.get('path')}")
    record("--json reports no unreadable policy elements",
           doc.get("unreadable_policy_elements") == 0,
           f"unreadable={doc.get('unreadable_policy_elements')}")

    p = cli("rules", PLAIN)
    record("an unfiltered workload is refused with a nonzero code",
           p.returncode == 1,
           f"rc={p.returncode} {(p.stdout + p.stderr).strip()[:100]}")


# --- T8: doctor --------------------------------------------------------------

def doctor_figures():
    """doctor's egress figures for NAME, as JSON. Also the T8 assertions."""
    say("== T8: doctor's egress section ==")
    p = cli("doctor", NAME, "--json", timeout=300)
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        record("doctor --json parses", False, (p.stdout + p.stderr)[:200])
        return {}
    egress = doc.get("egress") or {}
    figs = egress.get("figures") or {}
    record("doctor reports the inspector's status document as present",
           egress.get("status_present") is True,
           f"status_present={egress.get('status_present')}")
    record("the counters MOVED — a reader stuck at zero passes every "
           "zero-shaped assertion",
           figs.get("connections_total", 0) > 0,
           f"connections_total={figs.get('connections_total')} "
           f"terminated={figs.get('terminated')} "
           f"dropped={figs.get('dropped')}")
    record("something was dropped, so the denial half of the document is real",
           figs.get("drops_total", 0) > 0,
           f"drops_total={figs.get('drops_total')} "
           f"reasons={ {k: v for k, v in (egress.get('drop_reasons') or {}).items() if v} }")
    record("the minter reported, because this workload terminates",
           "mints" in figs,
           f"mints={figs.get('mints')} hits={figs.get('hits')}")
    record("doctor names the policy the listener actually loaded",
           bool(egress.get("policy_digest")),
           f"digest={str(egress.get('policy_digest'))[:16]}")

    p = cli("doctor", NAME, timeout=300)
    text = p.stdout
    record("the human report prints the section and disclaims a verdict",
           "Egress (inspected)" in text and "evidence, not a verdict" in text,
           next((l.strip() for l in text.splitlines()
                 if "evidence, not" in l), text[:120]))
    # THE POINT OF THE DISCLAIMER, tested rather than trusted: the run above
    # dropped at least one connection, and doctor's verdict must not have moved
    # because of it. A doctor that went UNHEALTHY over a drop count would teach
    # an operator that the filter working is a fault.
    unhealthy_for_drops = ("Overall: UNHEALTHY" in text
                           and not [c for c in doc.get("checks", [])
                                    if not c.get("passed")])
    record("a dropped connection did not make the workload UNHEALTHY",
           not unhealthy_for_drops,
           next((l for l in text.splitlines() if l.startswith("Overall:")),
                "(no verdict line)"))

    p = cli("doctor", PLAIN, "--json", timeout=300)
    try:
        plain = json.loads(p.stdout)
    except ValueError:
        plain = {}
    record("an unfiltered workload gets no egress section at all",
           plain.get("egress", "missing") is None,
           f"egress={plain.get('egress', 'missing')!r}")
    return figs


# --- T9: the exporter --------------------------------------------------------

SAMPLE = re.compile(r"^([a-z_0-9]+)\{([^}]*)\}\s+(\S+)$")


def parse_exposition(text):
    """{(metric, labels): value} plus the family order, as Prometheus reads it."""
    samples, order = {}, []
    for line in text.splitlines():
        m = SAMPLE.match(line.strip())
        if not m:
            continue
        metric, labels, value = m.groups()
        samples[(metric, labels)] = value
        order.append(metric)
    return samples, order


def exporter_checks(doctor_figs):
    say("== T9: the exporter, and decision 9 across both renderers ==")
    with tempfile.NamedTemporaryFile(suffix=".prom") as tmp:
        p = run([EXPORTER, tmp.name], check=False, timeout=300)
        text = Path(tmp.name).read_text()
    record("the exporter ran against the installed tree",
           p.returncode == 0 and bool(text),
           f"rc={p.returncode} bytes={len(text)} {p.stderr[:120]}")

    samples, order = parse_exposition(text)
    mine = {(m, l): v for (m, l), v in samples.items()
            if m.startswith("workload_vm_inspect_") and f'workload="{NAME}"' in l}
    record("the inspected workload has inspector series",
           bool(mine),
           f"{len(mine)} series for {NAME}")
    record("status_present is 1 for a listener that has written its document",
           samples.get(("workload_vm_inspect_status_present",
                        f'workload="{NAME}"')) == "1",
           f"status_present="
           f"{samples.get(('workload_vm_inspect_status_present', f'workload=\"{NAME}\"'))}")
    plain_series = [m for (m, l) in samples
                    if m.startswith("workload_vm_inspect_")
                    and f'workload="{PLAIN}"' in l]
    record("an UNFILTERED workload gets no inspector series — a series would "
           "assert a filter exists and is idle",
           not plain_series,
           f"{len(plain_series)} series for {PLAIN}")

    reasons = [l for (m, l) in samples
               if m == "workload_vm_inspect_drop_events_total"
               and f'workload="{NAME}"' in l]
    record("the drop breakdown reaches the wire with its reason label",
           bool(reasons),
           f"{len(reasons)} reason series, e.g. {reasons[0] if reasons else '-'}")

    # Exposition validity. node_exporter's textfile collector drops the WHOLE
    # file on a malformed one, so a single interleaved family costs every metric
    # on the host, not one series.
    runs = [m for i, m in enumerate(order) if i == 0 or order[i - 1] != m]
    record("every family's samples are contiguous, so the file parses at all",
           len(runs) == len(set(order)),
           f"{len(runs)} runs over {len(set(order))} families")
    headered = True
    for metric in {m for (m, _l) in mine}:
        if f"# TYPE {metric} " not in text or f"# HELP {metric} " not in text:
            headered = False
            break
    record("every inspector family carries HELP and TYPE", headered,
           "all headered" if headered else f"{metric} has none")

    # THE CROWN JEWEL, and the only check here that needs both surfaces at once:
    # decision 9 says one producer, and the unit suite proves the two renderers
    # agree about a document written by hand. Agreeing about a LIVE one is a
    # different claim — it needs both to have opened the same file, through
    # their own code paths, and come back with the same numbers.
    disagreements = []
    for key, metric in (("terminated", "workload_vm_inspect_terminated_total"),
                        ("dropped", "workload_vm_inspect_dropped_total"),
                        ("spliced", "workload_vm_inspect_spliced_total"),
                        ("mints", "workload_vm_inspect_mints_total"),
                        ("record_failures",
                         "workload_vm_inspect_record_failures_total")):
        if key not in doctor_figs:
            continue
        published = samples.get((metric, f'workload="{NAME}"'))
        if published is None or int(published) != doctor_figs[key]:
            disagreements.append(f"{key}: doctor={doctor_figs[key]} "
                                 f"exporter={published}")
    record("doctor and the exporter report the SAME figures for the same "
           "live workload (decision 9)",
           not disagreements,
           "; ".join(disagreements) if disagreements
           else "every compared figure agrees")
    # Not a flake guard, a statement about what was compared: the two surfaces
    # read the file at different instants, so a figure that moved between them
    # would show here as a disagreement. Both reads happen after the guest has
    # stopped dialling, which is what makes the comparison legitimate.
    record("the comparison had figures to compare",
           len([k for k in ("terminated", "dropped", "mints")
                if k in doctor_figs]) >= 2,
           f"compared {sorted(set(doctor_figs) & {'terminated', 'dropped', 'spliced', 'mints', 'record_failures'})}")


def teardown():
    say("== teardown ==")
    for arm in ARMS:
        subprocess.run(["workloadctl", "disable", arm.name, "--purge"],
                       capture_output=True, text=True, timeout=300)
        shutil.rmtree(Path("/etc/workloads.d") / arm.name, ignore_errors=True)
        say(f"  purged {arm.name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the guests running for inspection")
    ap.add_argument("--no-deploy", action="store_true",
                    help="reuse guests left by an earlier --keep run")
    ap.add_argument("--quiet", action="store_true",
                    help="print only failures and the tally")
    args = ap.parse_args()
    global QUIET
    QUIET = args.quiet

    preflight()
    try:
        if not args.no_deploy:
            deploy()
        drive_traffic()
        rules_checks()
        figs = doctor_figures()
        exporter_checks(figs)
    except BaseException:
        _show_section()
        raise
    finally:
        if not args.keep:
            teardown()

    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed", flush=True)
    if not QUIET:
        for label, _, detail in bad:
            print(f"  FAIL  {label}: {detail}", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
