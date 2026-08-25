"""The per-workload proxy is gone, asserted as an absence across the tree.

WHY A WHOLE MODULE FOR A DELETION

Rung 2 replaced a proxy the guest had to be configured to use with a redirect
the guest is not told about. Every other test in this suite asserts that the
replacement WORKS. None of them can fail if a piece of the old path is still
present, because the old path was never wrong -- it was superseded. A leftover
tinyproxy unit, a surviving map element, a seed still exporting `https_proxy`:
each of those runs happily beside the inspector, and a suite that only checks
the new mechanism stays green while a host runs both.

That is the specific failure this module exists for, and it is why these
assertions are written against the SOURCE TREE rather than against behaviour.
Behaviour cannot see a file that is still packaged but no longer called.

WHY THE NEGATIVE BELONGS HERE AND NOT A RUNG EARLIER

Written before the deletion it would have failed against a tree where the old
path was deliberately still present, and the way that gets "fixed" is by pulling
the deletion forward -- which is the pressure the build order was written to
resist. So it arrives with the deletion, in the same commit, and from here on it
is what keeps the old path from coming back one file at a time.

WHAT IS DELIBERATELY *NOT* ASSERTED HERE

The strings "proxy" and "workload_proxy" survive all over the tree, and that is
correct: the nat table, its skeleton file and the dummy link kept their names
because they are kernel and packaging objects on running hosts, and renaming
them would be a migration that buys a better name and nothing else. The
assertions below are about the SERVICE, its endpoint and its environment --
things a guest can dial or read -- never about the word.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The endpoint the guest was told to use. Spelled literally rather than imported
# from lib/vm.py, because the constant it came from is deleted -- and a test
# that imported its replacement would assert nothing about the retired value.
RETIRED_ENDPOINT = "192.0.2.1:3128"
RETIRED_PORT = "3128"

# The six variables the seed used to export. Same reasoning: named literally,
# because there is no constant left to import them from.
RETIRED_ENV_VARS = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                    "no_proxy", "NO_PROXY")

# Every tracked directory that ships or generates behaviour. `docs/` is not
# here: prose describing what the design used to do is the point of the docs,
# and rung 2's documentation pass is its own commit.
#
# `workloads/` IS here, and only partly -- the VM bundles. The container
# workloads under it (squid, proxy-stack, socks5-vpn) are ordinary HTTP proxies
# an operator runs on purpose, and they use port 3128 because that is the
# conventional proxy port. Sweeping them in would make this module fail for
# reasons that have nothing to do with VM egress.
CODE_DIRS = ("bin", "lib", "generators", "libexec", "nftables", "security",
             "rpm")
VM_BUNDLES = ("workloads/vm-base", "workloads/virtual-forgejo")


def _tracked_files():
    """Every file this module sweeps, as (relative path, text).

    Found rather than listed. A hard-coded list is the same decay one level up:
    a file added later would not be covered and nothing would say so.
    """
    seen = []
    for rel in CODE_DIRS + VM_BUNDLES:
        base = ROOT / rel
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            try:
                seen.append((path.relative_to(ROOT), path.read_text()))
            except (UnicodeDecodeError, OSError):
                continue
    return seen


class TestTheDeletedArtifacts(unittest.TestCase):
    """The four tracked files T7 removes, checked by absence.

    A file that came back would not fail anything else: nothing imports these
    any more, so a restored copy is inert until somebody wires it up, and by
    then the reason it was deleted is a git message nobody read.
    """

    def test_the_helper_is_gone(self):
        self.assertFalse((ROOT / "libexec" / "workload-vm-proxy").exists())

    def test_its_test_module_is_gone(self):
        """Deleted with it rather than left skipping. A module that skips
        reads, in a run's summary, exactly like one that is waiting on a host
        it cannot find."""
        self.assertFalse((ROOT / "tests" / "test_vm_proxy.py").exists())

    def test_the_selinux_module_is_gone(self):
        """wlproxy_t was defined by the binary it entrypointed and the
        filesystem boundary it held, and rung 2 deleted both. There was nothing
        left for the module to declare, so it is removed rather than rewritten
        around a domain with no process in it."""
        self.assertFalse((ROOT / "security" / "workload-proxy.cil").exists())

    def test_nothing_still_packages_them(self):
        spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        install_and_files = [ln for ln in spec.splitlines()
                             if not ln.lstrip().startswith("#")]
        text = "\n".join(install_and_files)
        self.assertNotIn("workload-vm-proxy", text)
        self.assertNotIn("workload-proxy.cil", text)


class TestTheRetiredEndpoint(unittest.TestCase):
    """192.0.2.1:3128 is not produced by anything that ships.

    The address itself survives -- it carries the credential broker -- so the
    assertion is on the PAIR. Asserting on the address alone would fail on the
    broker; asserting on the port alone would fail on the container workloads
    that legitimately run a proxy there.
    """

    def test_no_shipped_file_emits_the_retired_endpoint(self):
        offenders = [str(rel) for rel, text in _tracked_files()
                     if RETIRED_ENDPOINT in text]
        self.assertEqual(offenders, [], (
            f"{RETIRED_ENDPOINT} is the endpoint rung 2 retired. A guest told "
            f"to dial it reaches a host address where nothing listens."))

    def test_the_nat_skeleton_has_no_rule_for_the_retired_port(self):
        """The map element and the rule that read it are both gone. A surviving
        rule would be inert with the map deleted -- and would fail to load,
        taking every workload's redirect down with it."""
        text = (ROOT / "nftables" / "workload-proxy.nft").read_text()
        self.assertNotIn("wl_proxy_dest", text)
        rules = [ln for ln in text.splitlines() if ln.startswith("add rule")]
        for rule in rules:
            self.assertNotIn(f"dport {RETIRED_PORT}", rule, rule)

    def test_the_port_53_carve_out_survived(self):
        """The one piece of the proxy's plumbing that had to STAY.

        It was written for tinyproxy's name resolution and reads like the
        proxy's, so deleting it with the proxy is the obvious mistake. The
        inspector resolves host-side on every connection it authorises,
        permanently -- so removing this drops every lookup it makes, and
        hostname policy dies on the rung that was meant to strengthen it.

        The synthesising responder is NOT a second beneficiary, though the
        comments here used to say so: it answers from memory and looks nothing
        up. See TestGeneratedUnits in tests/test_vm_resolve.py.
        """
        text = (ROOT / "nftables" / "workload-filter.nft").read_text()
        carve = [ln for ln in text.splitlines()
                 if ln.startswith("add rule") and "wl_egress_cg" in ln
                 and "th dport 53" in ln and ln.rstrip().endswith("accept")]
        self.assertEqual(len(carve), 1, (
            "the port-53 carve-out for wl_egress_cg is missing. The inspector "
            "resolves host-side on every connection it authorises; without "
            "it every lookup it makes is dropped."))


class TestTheGuestIsToldNothing(unittest.TestCase):
    """No shipped seed exports a proxy variable.

    THE NEGATIVE TEST THIS RUNG OWES, at the level a unit test can reach. The
    live half -- a guest that SETS the variable and reaches nothing -- is in
    tests/cli_surface/test_runtime_vm_hostname_policy.py, which needs a booted
    VM. This half is what runs on every PR.
    """

    def test_vm_ca_env_writes_no_proxy_variable(self):
        from vm import vm_ca_env
        env = vm_ca_env({"vm": {"network": {"egress": "filtered",
                                            "hosts": ["example.com"]}}})
        for var in RETIRED_ENV_VARS:
            self.assertNotIn(var, env)

    def test_the_default_seed_builder_writes_no_proxy_variable(self):
        """Asserted on the SOURCE of the seed renderer rather than on its
        output, because the output is empty at this rung -- vm_ca_env returns
        {} until rung 3 mints the CA, so a check on the rendered text would
        pass against a renderer that still had the block in it."""
        source = (ROOT / "libexec" / "workload-ensure-user").read_text()
        body = source[source.index("def _render_default_user_data"):]
        body = body[:body.index("\ndef ")]
        for var in RETIRED_ENV_VARS:
            self.assertNotIn(f"{var}=", body, (
                f"the default seed renderer still emits {var}"))

    def test_seed_provides_no_longer_accepts_the_proxy_concern(self):
        from vm import SEED_PROVIDES_CHOICES, SEED_PROVIDES_RETIRED
        self.assertNotIn("proxy", SEED_PROVIDES_CHOICES)
        self.assertIn("proxy", SEED_PROVIDES_RETIRED)
        # Named, not just refused: a custom seed that declared the old concern
        # DOES provide something, and the generic unknown-entry message would
        # send its author hunting a typo they did not make.
        self.assertIn(SEED_PROVIDES_RETIRED["proxy"], SEED_PROVIDES_CHOICES)


class TestTheServiceIsNotGenerated(unittest.TestCase):
    """No code path emits a proxy unit, and the removable view still names one.

    Those two are not in tension. /run/systemd/system is tmpfs, so a reboot
    clears the previous version's unit -- but an in-place RPM upgrade does not,
    and the stale unit is still running a tinyproxy this version stopped
    packaging. Listing it with present=False is what lets `workloadctl remove`
    unlink it. Generating it would be the bug; forgetting it would strand it.
    """

    def test_the_generator_has_no_proxy_service_builder(self):
        source = (ROOT / "generators" / "workload-generate").read_text()
        self.assertNotIn("def generate_vm_proxy_service", source)
        self.assertNotIn("workload-vm-proxy", source)

    def test_the_removable_view_still_unlinks_a_stale_proxy_unit(self):
        source = (ROOT / "lib" / "workload_lib.py").read_text()
        self.assertIn('"unit", "proxy", False', source, (
            "the migration entry for the retired proxy unit is gone. A host "
            "upgraded in place keeps the previous version's "
            "workload-<name>-proxy.service with nothing that knows its name."))


class TestThePolicyModuleIsRemovedOnUpgrade(unittest.TestCase):
    """%post removes workload-proxy, unguarded on $1.

    %postun's module removals are guarded on an erase, which is right for the
    modules the package still ships. This one it no longer ships, so on an
    UPGRADE nothing else would ever take it out: the host keeps a loaded
    wlproxy_t whose filecon labels /usr/bin/tinyproxy for a domain no unit
    enters, indefinitely.
    """

    def setUp(self):
        self.spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        post = self.spec.index("\n%post")
        self.post = self.spec[post:self.spec.index("\n%postun")]

    def test_post_removes_the_module(self):
        self.assertIn("semodule -r workload-proxy", self.post)

    def test_post_relabels_the_binary_it_had_retyped(self):
        """Removing the module drops its filecon, but the installed binary
        keeps wlproxy_exec_t until something relabels it -- leaving a file
        labelled for a type that no longer exists on any host that still has
        tinyproxy."""
        self.assertIn("restorecon /usr/bin/tinyproxy", self.post)

    def test_the_removal_is_not_guarded_on_a_fresh_install(self):
        """The whole point is the upgrade. A `[ $1 -eq 1 ]` guard around it
        would remove the module on exactly the installs that never had it."""
        block = self.post[self.post.index("semodule -r workload-proxy") - 400:
                          self.post.index("semodule -r workload-proxy")]
        self.assertNotIn('"$1"', block)
        self.assertNotIn("[ $1 ", block)

    def test_postun_no_longer_removes_it_twice(self):
        postun = self.spec[self.spec.index("\n%postun"):]
        postun = postun[:postun.index("\n%files")]
        self.assertNotIn("workload-proxy", postun)


if __name__ == "__main__":
    unittest.main()
