"""§9's synthesising responder: the wire details that present as "DNS is slow".

Every failure this file guards against looks like something else from inside
the guest. A REFUSED where NODATA belongs costs a full retry schedule per
lookup on a resolver list with exactly one entry; a static-map miss sends an
`allow`-by-name destination to a port the inspector does not serve, which hangs
rather than refuses; a TTL that is not the stated constant turns one lookup into
thousands. None of them produce an error message naming DNS.

The one property that is not a wire detail is asserted here too: the responder
has no upstream socket at all. That is what makes DNS exfiltration ABSENT
rather than filtered, and it is a property of the source text, so it is checked
as one.
"""

import ipaddress
import json
import os
import shutil
import socket
import struct
import tempfile
import unittest
from pathlib import Path

from vm import (
    UID_MAX, UID_MIN, VM_MGMT_NETWORK, VM_SIDECAR_SLICE, VM_RESOLVE_ADDR_BASE,
    VM_RESOLVE_LISTENER_BIN, VM_RESOLVE_POLICY_FILE, VM_RESOLVE_PORT,
    VM_RESOLVE_TTL, vm_allow_resolved, vm_filter_elements, vm_inspect_address,
    vm_management_address, vm_reserved_plane, vm_resolve_address,
    vm_resolve_policy, vm_resolve_policy_path, vm_uses_resolve,
)

UID = 10004  # the worked example the rest of the inspect tests use

TYPE_A = 1
TYPE_AAAA = 28
TYPE_MX = 15
TYPE_TXT = 16
TYPE_HTTPS = 65
CLASS_IN = 1
CLASS_CH = 3


def net_config(**net):
    return {"vm": {"network": net}}


def encode_name(name):
    """Presentation form to wire form.

    The trailing root dot is stripped, because it does not exist on the wire:
    a zero-length label IS the terminator, so `example.com.` and `example.com`
    are the same bytes. Normalising it is still the responder's job for names
    that reach it from a hand-edited policy file -- see
    test_a_hand_edited_map_key_is_normalised_on_load -- but no query can carry
    one, and a test that pretended otherwise would be asserting about a message
    no client can send.
    """
    name = name[:-1] if name.endswith(".") else name
    out = bytearray()
    for label in name.split(".") if name else []:
        out.append(len(label))
        out += label.encode("ascii")
    out.append(0)
    return bytes(out)


def query(name, qtype, ident=0x1234, rd=True, opcode=0, qdcount=1, opt=False,
          qclass=CLASS_IN):
    """A DNS query on the wire, with the knobs the tests below vary."""
    flags = (opcode << 11) | (0x0100 if rd else 0)
    arcount = 1 if opt else 0
    msg = struct.pack("!HHHHHH", ident, flags, qdcount, 0, 0, arcount)
    msg += encode_name(name) + struct.pack("!HH", qtype, qclass)
    if opt:
        # OPT: root name, type 41, class = advertised UDP payload size, no
        # options. The shape systemd-resolved actually sends.
        msg += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return msg


class Reply:
    """A parsed response, so assertions read as claims about DNS."""

    def __init__(self, raw):
        self.raw = raw
        (self.id, self.flags, self.qdcount, self.ancount,
         self.nscount, self.arcount) = struct.unpack("!HHHHHH", raw[:12])
        self.rcode = self.flags & 0x000F
        self.qr = bool(self.flags & 0x8000)
        self.aa = bool(self.flags & 0x0400)
        self.tc = bool(self.flags & 0x0200)
        self.rd = bool(self.flags & 0x0100)
        self.ra = bool(self.flags & 0x0080)
        self.opcode = (self.flags >> 11) & 0xF
        self.records = []
        offset = 12
        for _ in range(self.qdcount):
            offset = self._skip_name(offset) + 4
        for _ in range(self.ancount):
            offset = self._skip_name(offset)
            rtype, rclass, ttl, rdlen = struct.unpack(
                "!HHIH", raw[offset:offset + 10])
            offset += 10
            rdata = raw[offset:offset + rdlen]
            offset += rdlen
            self.records.append((rtype, rclass, ttl, rdata))

    def _skip_name(self, offset):
        while True:
            length = self.raw[offset]
            if length & 0xC0:
                return offset + 2
            offset += 1
            if length == 0:
                return offset
            offset += length

    def addresses(self):
        out = []
        for rtype, _rclass, _ttl, rdata in self.records:
            family = socket.AF_INET6 if rtype == TYPE_AAAA else socket.AF_INET
            out.append(socket.inet_ntop(family, rdata))
        return out


def _module():
    """The responder, with its per-query logging captured rather than printed.

    Silenced here rather than left to print through the suite: it is one line
    per answer and the tests below build thousands. The log is not thereby
    untested -- TestLogging asserts what it says, reading the same list.
    """
    from tests import load_script
    mod = load_script("libexec/workload-vm-resolve")
    mod.logged = []
    mod.log = mod.logged.append
    return mod


def _policy(mod, **overrides):
    doc = vm_resolve_policy({}, UID)
    doc.update(overrides)
    return mod.Policy(doc)


class TestAddress(unittest.TestCase):
    """The uid-derived responder address, and the reservation it inherits."""

    def test_the_offset_is_the_uid_offset(self):
        self.assertEqual(vm_resolve_address(UID_MIN), "127.130.0.0")
        self.assertEqual(vm_resolve_address(UID_MIN + 3), "127.130.0.3")
        self.assertEqual(vm_resolve_address(UID),
                         str(ipaddress.IPv4Address(
                             VM_RESOLVE_ADDR_BASE + (UID - UID_MIN))))

    def test_a_uid_outside_the_workload_range_is_refused(self):
        for uid in (UID_MIN - 1, UID_MAX + 1, 0):
            with self.assertRaises(ValueError):
                vm_resolve_address(uid)

    def test_the_whole_range_stays_inside_the_management_reservation(self):
        """Why there is no new ReservedPlane for the responder.

        The management /9 was cut wide on purpose -- its own comment says the
        planes hung on loopback after it would inherit the reservation. If this
        ever stopped holding, `ports` could bind a guest port on another
        workload's nameserver and start order would decide which one answered,
        with nothing logged either way.
        """
        for uid in (UID_MIN, UID, UID_MAX):
            addr = ipaddress.IPv4Address(vm_resolve_address(uid))
            self.assertIn(addr, VM_MGMT_NETWORK, uid)

    def test_ports_cannot_bind_a_responder_address(self):
        """The reservation, exercised through the check `ports` actually uses
        rather than asserted about the network object."""
        self.assertIsNotNone(
            vm_reserved_plane(vm_resolve_address(UID), VM_RESOLVE_PORT))

    def test_it_does_not_collide_with_the_management_address(self):
        """Same arithmetic, different base. A shared base would put the
        responder on the management address at a different port, which is a
        second service inside a plane documented as never configurable."""
        for uid in (UID_MIN, UID, UID_MAX):
            self.assertNotEqual(vm_resolve_address(uid),
                                vm_management_address(uid))

    def test_the_address_is_loopback(self):
        """Not the 198.18.0.0/16 advertised link. 127/8 is unreachable from the
        guest by construction, so passt's interception is the only path to the
        responder -- an address the guest could dial directly is a nameserver
        every other workload on the host can query too."""
        self.assertTrue(
            ipaddress.IPv4Address(vm_resolve_address(UID)).is_loopback)


class TestPredicate(unittest.TestCase):
    """vm_uses_resolve: the inspector's terms plus `resolver` not "none"."""

    def test_a_filtered_vm_gets_one_by_default(self):
        self.assertTrue(vm_uses_resolve(net_config()))
        self.assertTrue(vm_uses_resolve(net_config(egress="filtered")))

    def test_resolver_none_switches_it_off(self):
        self.assertFalse(vm_uses_resolve(net_config(resolver="none")))

    def test_resolver_host_keeps_it_on(self):
        self.assertTrue(vm_uses_resolve(net_config(resolver="host")))

    def test_open_egress_does_not_get_one(self):
        """A responder under `egress = "open"` would answer every name with an
        inspector address that nothing redirects to."""
        self.assertFalse(vm_uses_resolve(net_config(egress="open")))
        self.assertFalse(
            vm_uses_resolve(net_config(egress="open", resolver="host")))

    def test_a_bridged_vm_does_not_get_one(self):
        self.assertFalse(vm_uses_resolve(net_config(bridge="br0")))

    def test_a_container_workload_does_not_get_one(self):
        self.assertFalse(vm_uses_resolve({"container": {"image": "x"}}))
        self.assertFalse(vm_uses_resolve({}))


class TestPolicyDocument(unittest.TestCase):
    """What the arming path writes for the responder to read."""

    def test_the_synthesised_addresses_are_the_inspectors(self):
        doc = vm_resolve_policy({}, UID)
        inspect = vm_inspect_address(UID)
        self.assertEqual(doc["address"], inspect.v4)
        self.assertEqual(doc["address6"], inspect.v6)

    def test_the_ttl_is_the_stated_constant(self):
        self.assertEqual(vm_resolve_policy({}, UID)["ttl"], VM_RESOLVE_TTL)

    def test_the_ttl_is_pinned_to_a_number_and_not_to_itself(self):
        """The literal, because every other assertion about the TTL reads the
        constant and so is true of any value it holds. Changing 3600 to 30 left
        the whole suite green: a guest would then re-ask for every name every
        thirty seconds, which is a load and a latency problem that looks like
        the responder being slow rather than like a constant being wrong.

        The lower bound carries the reasoning rather than the number: the
        inspector's address never moves, so there is no upstream truth for a
        short TTL to track and nothing a small value buys. An hour is also
        below the ceiling stubs clamp cached TTLs to, which is what keeps the
        stated constant and the constant in effect the same value.
        """
        self.assertEqual(VM_RESOLVE_TTL, 3600)
        self.assertGreaterEqual(VM_RESOLVE_TTL, 3600)

    def test_an_address_form_allow_entry_is_not_in_the_map(self):
        """`allow` by address names no hostname, so there is nothing to answer
        for -- and inventing a name for it would be a name the operator never
        wrote."""
        net = {"allow": [{"address": "192.0.2.7:2222", "reason": "forge"}]}
        self.assertEqual(vm_resolve_policy(net, UID)["static"], {})

    def test_a_named_allow_entry_lands_in_the_map(self):
        resolved = [(_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9")])]
        doc = vm_resolve_policy({}, UID, resolved)
        self.assertEqual(doc["static"], {"git.local": ["192.0.2.9"]})

    def test_the_map_key_is_normalised(self):
        """One name, one entry, whatever the operator typed. Two spellings
        becoming two keys is a lookup that misses for the spelling the guest
        used."""
        resolved = [(_entry("Git.Local.", 2222),
                     [ipaddress.IPv4Address("192.0.2.9")])]
        self.assertEqual(list(vm_resolve_policy({}, UID, resolved)["static"]),
                         ["git.local"])

    def test_both_families_of_one_name_are_kept(self):
        resolved = [(_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9"),
                      ipaddress.IPv6Address("2001:db8::9")])]
        self.assertEqual(vm_resolve_policy({}, UID, resolved)["static"],
                         {"git.local": ["192.0.2.9", "2001:db8::9"]})

    def test_the_map_and_the_nft_elements_come_from_one_resolution(self):
        """The whole reason vm_allow_resolved is a function of its own.

        A second, independent resolution is the same name asked twice, and a
        round-robin or short-TTL record answering differently the second time
        sends the guest to an address the set does not hold -- which is a hang
        against the default-deny drop, not a refusal. Here one resolution feeds
        both, and every address the responder would hand out is in the set.
        """
        resolved = [(_entry("git.local", 2222),
                     [ipaddress.IPv4Address("192.0.2.9"),
                      ipaddress.IPv4Address("192.0.2.10")])]
        elements = vm_filter_elements(UID, [], resolved)
        armed = {e.split(" . ")[1] for e in elements["wl_allow4"]}
        served = set(vm_resolve_policy({}, UID, resolved)["static"]["git.local"])
        self.assertEqual(served, armed)

    def test_resolution_is_shared_by_default_too(self):
        """vm_filter_elements without a `resolved` still resolves for itself,
        so every pre-existing caller is unchanged."""
        net = {"allow": [{"address": "192.0.2.7:2222", "reason": "forge"}]}
        self.assertEqual(vm_filter_elements(UID, net["allow"]),
                         vm_filter_elements(UID, net["allow"],
                                            vm_allow_resolved(net["allow"])))

    def test_the_policy_path_is_beside_the_inspectors(self):
        path = vm_resolve_policy_path("web")
        self.assertTrue(path.endswith(f"/web/{VM_RESOLVE_POLICY_FILE}"), path)


def _entry(host, port):
    from vm import VmAllowEntry
    return VmAllowEntry(address=None, host=host, port=port, reason="test")


class TestSynthesis(unittest.TestCase):
    """Every A/AAAA, for any name, answered with the inspector's address."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        cls.policy = _policy(cls.mod)
        cls.inspect = vm_inspect_address(UID)

    def answer(self, *args, **kwargs):
        return Reply(self.mod.build_answer(query(*args, **kwargs), self.policy))

    def test_an_a_query_gets_the_inspectors_v4(self):
        reply = self.answer("example.com", TYPE_A)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.addresses(), [self.inspect.v4])

    def test_an_aaaa_query_gets_the_inspectors_v6(self):
        self.assertEqual(self.answer("example.com", TYPE_AAAA).addresses(),
                         [self.inspect.v6])

    def test_any_name_at_all_is_answered(self):
        """There are no names we do not serve. A responder that answered only
        for names on a list would need a fallback for the rest, and a fallback
        is an upstream socket."""
        for name in ("a.b.c.d.example", "nonexistent.invalid", "x"):
            self.assertEqual(self.answer(name, TYPE_A).addresses(),
                             [self.inspect.v4], name)

    def test_the_ttl_on_the_wire_is_the_stated_constant(self):
        _rtype, _rclass, ttl, _rdata = self.answer("example.com",
                                                   TYPE_A).records[0]
        self.assertEqual(ttl, VM_RESOLVE_TTL)

    def test_the_id_and_question_are_echoed(self):
        raw = self.mod.build_answer(query("example.com", TYPE_A, ident=0xBEEF),
                                    self.policy)
        reply = Reply(raw)
        self.assertEqual(reply.id, 0xBEEF)
        self.assertEqual(reply.qdcount, 1)
        self.assertEqual(raw[12:12 + len(encode_name("example.com")) + 4],
                         encode_name("example.com")
                         + struct.pack("!HH", TYPE_A, CLASS_IN))

    def test_the_answer_is_a_response_and_authoritative(self):
        reply = self.answer("example.com", TYPE_A)
        self.assertTrue(reply.qr)
        self.assertTrue(reply.aa)
        self.assertFalse(reply.tc)

    def test_recursion_desired_is_echoed_and_available_is_set(self):
        """RA is set because recursion IS available from the client's point of
        view: every name is answered here, with no referral. A stub that sees
        RD honoured with RA clear can decide the server is not usable for
        recursion and stop asking it -- which, with a one-entry resolver list,
        is the whole of DNS for that guest."""
        self.assertTrue(self.answer("example.com", TYPE_A, rd=True).rd)
        self.assertFalse(self.answer("example.com", TYPE_A, rd=False).rd)
        self.assertTrue(self.answer("example.com", TYPE_A).ra)



class TestNodata(unittest.TestCase):
    """NODATA, never REFUSED, for everything that is not an address."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        cls.policy = _policy(cls.mod)

    def answer(self, *args, **kwargs):
        return Reply(self.mod.build_answer(query(*args, **kwargs), self.policy))

    def test_https_gets_nodata_not_refused(self):
        """The type Firefox and curl now ask for before every connection. A
        REFUSED here costs a retry schedule on the first request of every
        page."""
        reply = self.answer("example.com", TYPE_HTTPS)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)

    def test_mx_gets_nodata_not_refused(self):
        reply = self.answer("example.com", TYPE_MX)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)

    def test_txt_gets_nodata_not_refused(self):
        self.assertEqual(self.answer("example.com", TYPE_TXT).rcode, 0)

    def test_nodata_echoes_the_question(self):
        """An empty answer with no question is not a NODATA, it is a reply a
        stub cannot match to anything it asked."""
        self.assertEqual(self.answer("example.com", TYPE_MX).qdcount, 1)

    def test_no_reply_is_ever_refused(self):
        """REFUSED reads as "this server is broken, try another", and the
        guest's resolver list has exactly one entry."""
        for qtype in (TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_TXT, TYPE_HTTPS, 99):
            self.assertNotEqual(self.answer("example.com", qtype).rcode, 5,
                                qtype)

    def test_a_non_internet_class_gets_nodata(self):
        """version.bind CH TXT and friends. Not an address question, so not an
        address answer -- and not a refusal either."""
        reply = self.answer("version.bind", TYPE_TXT, qclass=CLASS_CH)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)

    def test_an_a_query_in_a_non_internet_class_is_not_synthesised(self):
        self.assertEqual(self.answer("example.com", TYPE_A,
                                     qclass=CLASS_CH).ancount, 0)


class TestStaticMap(unittest.TestCase):
    """The `allow`-by-name map, which lands with the responder, not after it."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        cls.inspect = vm_inspect_address(UID)
        cls.policy = _policy(cls.mod, static={
            "git.local": ["192.0.2.9"],
            "dual.local": ["192.0.2.10", "2001:db8::10"],
        })

    def answer(self, *args, **kwargs):
        return Reply(self.mod.build_answer(query(*args, **kwargs), self.policy))

    def test_a_static_name_wins_over_synthesis(self):
        """Without this every named non-80/443 destination -- an SSH forge, a
        registry, an internal API -- is sent to a port the inspector does not
        serve, which presents as a healthy-looking hang."""
        self.assertEqual(self.answer("git.local", TYPE_A).addresses(),
                         ["192.0.2.9"])

    def test_a_name_not_in_the_map_is_still_synthesised(self):
        self.assertEqual(self.answer("elsewhere.example", TYPE_A).addresses(),
                         [self.inspect.v4])

    def test_the_map_wins_completely_for_a_family_it_lacks(self):
        """git.local has no v6 address, so AAAA is NODATA -- NOT the
        synthesised inspector address. Falling back to synthesis there sends
        the guest to a listener that does not serve port 2222, which hangs
        instead of refusing: the exact failure the map exists to prevent."""
        reply = self.answer("git.local", TYPE_AAAA)
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 0)
        self.assertNotIn(self.inspect.v6, reply.addresses())

    def test_a_dual_stack_name_answers_each_family_from_the_map(self):
        self.assertEqual(self.answer("dual.local", TYPE_A).addresses(),
                         ["192.0.2.10"])
        self.assertEqual(self.answer("dual.local", TYPE_AAAA).addresses(),
                         ["2001:db8::10"])

    def test_the_lookup_is_case_insensitive(self):
        """DNS names are case-insensitive and some resolvers randomise the case
        of a query deliberately (0x20 encoding). A case-sensitive map lookup
        would miss for exactly those clients, intermittently."""
        for spelling in ("GIT.local", "Git.Local", "git.LOCAL"):
            self.assertEqual(self.answer(spelling, TYPE_A).addresses(),
                             ["192.0.2.9"], spelling)

    def test_a_hand_edited_map_key_is_normalised_on_load(self):
        policy = _policy(self.mod, static={"GIT.Local.": ["192.0.2.9"]})
        reply = Reply(self.mod.build_answer(query("git.local", TYPE_A), policy))
        self.assertEqual(reply.addresses(), ["192.0.2.9"])


class TestEdns(unittest.TestCase):
    """A query carrying OPT gets a well-formed answer, without an OPT of ours."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        cls.policy = _policy(cls.mod)
        cls.inspect = vm_inspect_address(UID)

    def test_an_opt_query_is_answered(self):
        reply = Reply(self.mod.build_answer(
            query("example.com", TYPE_A, opt=True), self.policy))
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.addresses(), [self.inspect.v4])

    def test_no_opt_is_emitted(self):
        """The decision, not an accident. systemd-resolved reads a missing OPT
        as no EDNS0 support and downgrades once; a malformed or truncated OPT
        echoed back is what makes a stub mark a server bad -- with nowhere to
        fall back to."""
        reply = Reply(self.mod.build_answer(
            query("example.com", TYPE_A, opt=True), self.policy))
        self.assertEqual(reply.arcount, 0)
        self.assertNotIn(b"\x00\x29", reply.raw[12:])  # type 41, OPT

    def test_the_answer_is_identical_with_and_without_opt(self):
        """Everything past the question is ignored, which is the shape that
        cannot echo a malformed OPT."""
        with_opt = self.mod.build_answer(
            query("example.com", TYPE_A, opt=True), self.policy)
        without = self.mod.build_answer(
            query("example.com", TYPE_A, opt=False), self.policy)
        self.assertEqual(with_opt[2:], without[2:])


class TestMalformed(unittest.TestCase):
    """Defined replies to queries no stub sends."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        cls.policy = _policy(cls.mod)

    def test_a_non_query_opcode_gets_notimp(self):
        """An UPDATE or a NOTIFY is not a question about a name, so there is no
        empty answer that would mean anything."""
        reply = Reply(self.mod.build_answer(
            query("example.com", TYPE_A, opcode=5), self.policy))
        self.assertEqual(reply.rcode, 4)
        self.assertEqual(reply.opcode, 5)

    def test_a_query_with_no_question_gets_formerr(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)
        self.assertEqual(Reply(self.mod.build_answer(raw, self.policy)).rcode, 1)

    def test_a_compression_pointer_in_the_question_is_refused(self):
        """A pointer in a QUESTION section is malformed -- there is nothing
        earlier in the message for it to point at -- and following one is how a
        parser is walked into a loop by a peer that controls every byte."""
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        raw += b"\xc0\x0c" + struct.pack("!HH", TYPE_A, CLASS_IN)
        with self.assertRaises(self.mod.Malformed):
            self.mod.build_answer(raw, self.policy)

    def test_a_name_ending_exactly_at_the_message_boundary_is_refused(self):
        """Found by TestFuzz, pinned here.

        The last label consumes the final byte of the message, so the parser
        arrives at the position where the zero terminator should be and finds
        the message has ended. Without read_name's end-of-message guard that is
        an IndexError, not a Malformed -- and an exception the serve loops do
        not catch kills the process. For a guest with exactly one nameserver
        that is a denial of service it can trigger at will, one packet at a
        time, and it survives every restart because the next packet is the same
        packet.
        """
        raw = bytes.fromhex("00010100000100000000b9000100")
        with self.assertRaises(self.mod.Malformed):
            self.mod.build_answer(raw, self.policy)

    def test_a_truncated_header_is_refused(self):
        with self.assertRaises(self.mod.Malformed):
            self.mod.build_answer(b"\x12\x34", self.policy)

    def test_a_name_running_past_the_message_is_refused(self):
        raw = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x09abc"
        with self.assertRaises(self.mod.Malformed):
            self.mod.build_answer(raw, self.policy)

    def test_an_error_response_carries_the_queried_id(self):
        raw = self.mod.error_response(
            query("example.com", TYPE_A, ident=0x4242), 1)
        self.assertEqual(Reply(raw).id, 0x4242)
        self.assertTrue(Reply(raw).qr)


class TestLogInjectionViaLabel(unittest.TestCase):
    """A label the guest wrote must not be able to write a line of this log.

    A DNS label carries arbitrary bytes -- the wire format is length-prefixed,
    not delimited -- so a guest can put a bare LF in one. The name then reaches
    a `print()` whose destination is the journal, where an LF ends the record
    and turns the rest of the label into a second entry indistinguishable from
    one this responder wrote. The same name is carried into `unlisted_names`,
    which `diagnose` renders.

    Refused as malformed, which is a disposition this responder already has:
    the query gets FORMERR and the malformed counter, not a new bucket.
    """

    def setUp(self):
        self.mod = _module()
        self.policy = _policy(self.mod, hosts=["allowed.example"])

    _forged = "evil\n  allowed.example A -> static: 1 record(s)"

    def test_a_label_with_a_newline_is_malformed(self):
        with self.assertRaises(self.mod.Malformed):
            self.mod.build_answer(query(self._forged, TYPE_A), self.policy)

    def test_it_is_refused_before_it_is_logged_or_counted(self):
        counters = self.mod.Counters()
        with self.assertRaises(self.mod.Malformed):
            self.mod.build_answer(query(self._forged, TYPE_A), self.policy,
                                  counters=counters)
        self.assertEqual(self.mod.logged, [])
        snap = counters.snapshot()
        self.assertEqual(snap["unlisted_names"], {})

    def test_the_forged_text_appears_in_no_line_the_responder_writes(self):
        """serve_datagram logs the refusal itself, so the property has to hold
        over the refusal path too -- the name is not what it names."""
        sock = _RefusingSocket(query(self._forged, TYPE_A))
        counters = self.mod.Counters()
        self.mod.serve_datagram(sock, self.policy, counters=counters)
        self.assertEqual(Reply(sock.sent).rcode, 1)
        self.assertEqual(counters.snapshot()["queries"]["malformed"], 1)
        self.assertTrue(self.mod.logged)
        for line in self.mod.logged:
            self.assertNotIn("evil", line)
            self.assertNotIn("\n", line)

    def test_every_control_character_goes_with_the_newline(self):
        for ch in ("\n", "\r", "\x00", "\x7f", "\t", "\x1b"):
            with self.subTest(ch=ch):
                with self.assertRaises(self.mod.Malformed):
                    self.mod.build_answer(
                        query(f"a{ch}b.example", TYPE_A), self.policy)

    def test_an_ordinary_name_still_answers(self):
        """The guard must not cost the names that are not attacks -- including
        the hyphens and digits a real hostname carries."""
        reply = Reply(self.mod.build_answer(
            query("api-1.allowed.example", TYPE_A), self.policy))
        self.assertEqual(reply.rcode, 0)
        self.assertEqual(reply.ancount, 1)


class _RefusingSocket:
    """One datagram in, one datagram out. Enough of a socket for
    serve_datagram, which is where a malformed query is logged and counted."""

    def __init__(self, payload):
        self._payload = payload
        self.sent = None

    def recvfrom(self, _n):
        return self._payload, ("127.0.0.1", 5300)

    def sendto(self, data, _peer):
        self.sent = data


class TestUdpBudget(unittest.TestCase):
    """The one case that sets the truncate bit, and the retry it invites."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        # More v4 addresses than fit in 512 bytes at 16 bytes a record.
        cls.policy = _policy(cls.mod, static={
            "many.local": [f"192.0.2.{n}" for n in range(1, 60)]})

    def test_a_normal_answer_never_truncates(self):
        policy = _policy(self.mod)
        reply = Reply(self.mod.build_answer(
            query("example.com", TYPE_A), policy, budget=512))
        self.assertFalse(reply.tc)

    def test_an_oversized_udp_answer_truncates_rather_than_dropping_silently(self):
        """Records that do not fit are dropped WITH the bit set, which is what
        sends the client to the TCP listener the socket unit also binds.
        Dropping them quietly would hand the guest a partial answer it has no
        way to know is partial."""
        reply = Reply(self.mod.build_answer(
            query("many.local", TYPE_A), self.policy, budget=512))
        self.assertTrue(reply.tc)
        self.assertLess(reply.ancount, 59)
        self.assertLessEqual(len(reply.raw), 512)

    def test_tcp_is_not_bounded_and_carries_the_whole_answer(self):
        reply = Reply(self.mod.build_answer(query("many.local", TYPE_A),
                                            self.policy))
        self.assertFalse(reply.tc)
        self.assertEqual(reply.ancount, 59)


class TestNoUpstream(unittest.TestCase):
    """The property that makes DNS exfiltration absent rather than filtered."""

    def test_the_responder_never_calls_out(self):
        """Parsed, not grepped. The property is about CALLS, and the words
        naming them appear in this program's own prose explaining that it makes
        none -- a text search either trips over the docstring or gets weakened
        until it stops meaning anything. So the source is parsed and every call
        target is examined.

        If a future edit adds a "fallback for names we don't serve", this is
        what fails: the fallback IS the exfiltration channel.
        """
        import ast
        import pathlib
        source = pathlib.Path(__file__).resolve().parent.parent \
            / "libexec" / "workload-vm-resolve"
        tree = ast.parse(source.read_text())
        forbidden = {
            "connect", "connect_ex", "create_connection", "getaddrinfo",
            "gethostbyname", "gethostbyname_ex", "getnameinfo", "urlopen",
            "sendto_upstream",
        }
        called = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else \
                getattr(func, "id", None)
            if name:
                called.add(name)
        self.assertEqual(called & forbidden, set(), sorted(called & forbidden))

    def test_the_one_socket_constructor_only_adopts_an_inherited_fd(self):
        """socket.socket() appears exactly once, and only with `fileno=`.

        That call adopts a descriptor systemd already opened; the same
        constructor without `fileno=` would CREATE a socket, which is the one
        line that could turn this program into something that speaks to the
        network on its own initiative.
        """
        import ast
        import pathlib
        source = pathlib.Path(__file__).resolve().parent.parent \
            / "libexec" / "workload-vm-resolve"
        tree = ast.parse(source.read_text())
        constructions = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "socket"
        ]
        self.assertEqual(len(constructions), 1, ast.dump(tree)[:0] or
                         [ast.unparse(c) for c in constructions])
        self.assertEqual([kw.arg for kw in constructions[0].keywords],
                         ["fileno"])
        self.assertEqual(constructions[0].args, [])

    def test_the_only_socket_call_is_address_formatting(self):
        """inet_pton/inet_ntop are pure conversions. They are the only reason
        the socket module is imported at all in the answering path, and naming
        them here is what keeps the assertion above from being read as
        "the socket module is banned"."""
        mod = _module()
        self.assertEqual(mod.pack_address("192.0.2.1"), b"\xc0\x00\x02\x01")
        self.assertEqual(len(mod.pack_address("2001:db8::1")), 16)


class TestOnTheWire(unittest.TestCase):
    """Both transports, through real sockets.

    Everything above tests build_answer, which is where the DNS is. This tests
    the two functions that carry it -- and specifically the TCP length prefix,
    which is the half a UDP-shaped implementation gets wrong: a reply written
    without its two-byte prefix looks perfectly well-formed in a unit test of
    the message and hangs every client that reads one.
    """

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        cls.policy = _policy(cls.mod, static={"git.local": ["192.0.2.9"]})
        cls.inspect = vm_inspect_address(UID)

    def test_a_udp_query_is_answered_to_the_sender(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with server, client:
            server.bind(("127.0.0.1", 0))
            client.settimeout(5)
            client.sendto(query("example.com", TYPE_A), server.getsockname())
            self.mod.serve_datagram(server, self.policy)
            raw, _peer = client.recvfrom(4096)
        self.assertEqual(Reply(raw).addresses(), [self.inspect.v4])

    def test_a_tcp_query_is_answered_with_a_length_prefix(self):
        import threading
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            address = listener.getsockname()
            served = threading.Thread(
                target=self.mod.serve_stream, args=(listener, self.policy))
            served.start()
            try:
                with socket.create_connection(address, timeout=5) as client:
                    payload = query("git.local", TYPE_A)
                    client.sendall(struct.pack("!H", len(payload)) + payload)
                    prefix = client.recv(2)
                    length = struct.unpack("!H", prefix)[0]
                    raw = client.recv(length)
            finally:
                served.join(timeout=5)
        self.assertEqual(len(raw), length)
        self.assertEqual(Reply(raw).addresses(), ["192.0.2.9"])

    def test_a_tcp_connection_carries_more_than_one_query(self):
        """RFC 7766 clients reuse the connection. Closing after one answer
        makes every second lookup a new handshake, which is the shape that
        reads as the responder being flaky under load."""
        import threading
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            address = listener.getsockname()
            served = threading.Thread(
                target=self.mod.serve_stream, args=(listener, self.policy))
            served.start()
            replies = []
            try:
                with socket.create_connection(address, timeout=5) as client:
                    for name in ("git.local", "example.com"):
                        payload = query(name, TYPE_A)
                        client.sendall(
                            struct.pack("!H", len(payload)) + payload)
                        length = struct.unpack("!H", client.recv(2))[0]
                        replies.append(Reply(client.recv(length)))
            finally:
                served.join(timeout=5)
        self.assertEqual([r.addresses() for r in replies],
                         [["192.0.2.9"], [self.inspect.v4]])


class TestFuzz(unittest.TestCase):
    """Arbitrary bytes in, a reply or a Malformed out. Never anything else.

    THE REASON THIS EXISTS. Every alternative to writing this responder was an
    off-the-shelf DNS server, and the one real cost of not taking one is that
    the wire parser is ours -- dnsmasq's has been read by rather more people
    than this one has. What makes that cost payable is that build_answer is a
    pure bytes -> bytes function with no I/O behind it, so it can simply be
    fed garbage in bulk.

    The oracle is the contract the serve loops depend on: build_answer either
    raises Malformed -- which both loops catch and answer FORMERR to -- or
    returns a well-formed reply carrying the query's own id. Any OTHER
    exception escapes into the serve loop and kills the process, which for a
    guest with one nameserver is a self-inflicted denial of service it can
    trigger at will, one crafted packet at a time.

    Seeded and bounded so it is deterministic in the suite: the same inputs
    every run, no flake, 50,000 cases in about a quarter of a second. Set
    WLRESOLVE_FUZZ_ITERATIONS (and optionally WLRESOLVE_FUZZ_SEED) to soak it
    for longer by hand; 200,000 cases take about a second.

    The count is not a round number picked for comfort. read_name's
    end-of-message guard was deleted on purpose to see whether this would
    notice: at 5,000 cases it did not, and at 10,000 it did, reporting an
    IndexError on a name whose last label runs exactly to the end of the
    message. 50,000 is that threshold with room, and the input it found is
    pinned as a test of its own in TestMalformed rather than left to a random
    walk to rediscover.
    """

    ITERATIONS = int(os.environ.get("WLRESOLVE_FUZZ_ITERATIONS", "50000"))
    SEED = int(os.environ.get("WLRESOLVE_FUZZ_SEED", "0"))

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()
        # A deliberately awkward map: more addresses than fit in a UDP answer,
        # and both families, so the record-packing and budget paths are on the
        # hot path of the fuzz rather than skipped by a one-record answer.
        cls.policy = _policy(cls.mod, static={
            "git.local": [f"192.0.2.{n}" for n in range(1, 60)]
                         + [f"2001:db8::{n}" for n in range(1, 40)]})

    def _corpus(self, rng):
        """Seed queries the mutator starts from.

        Random bytes alone almost never produce a parseable question, so most
        of a purely random run would exercise the first four lines of
        build_answer and nothing else. These are valid messages; the mutator
        below breaks them in small ways, which is what reaches the code past
        the header.
        """
        names = ("git.local", "example.com", "", "a" * 63 + ".com",
                 ".".join("ab" for _ in range(120)))
        corpus = []
        for name in names:
            labels = b"".join(bytes([len(l)]) + l.encode()
                              for l in name.split(".") if l) + b"\x00"
            for qtype in (TYPE_A, TYPE_AAAA, TYPE_MX, TYPE_HTTPS):
                corpus.append(
                    struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels
                    + struct.pack("!HH", qtype, CLASS_IN))
        return corpus

    def _mutate(self, rng, corpus):
        if rng.randint(0, 2) == 0:
            return bytes(rng.getrandbits(8)
                         for _ in range(rng.randint(0, 80)))
        data = bytearray(rng.choice(corpus))
        for _ in range(rng.randint(1, 6)):
            op = rng.randint(0, 2)
            if op == 0 and data:
                data[rng.randrange(len(data))] = rng.getrandbits(8)
            elif op == 1:
                data.insert(rng.randint(0, len(data)), rng.getrandbits(8))
            elif data:
                del data[rng.randrange(len(data))]
        return bytes(data)

    def test_no_input_escapes_as_an_unexpected_exception(self):
        import random
        rng = random.Random(self.SEED)
        corpus = self._corpus(rng)
        for i in range(self.ITERATIONS):
            data = self._mutate(rng, corpus)
            budget = 512 if i % 2 else None
            try:
                reply = self.mod.build_answer(data, self.policy, budget=budget)
            except self.mod.Malformed:
                continue
            except Exception as exc:  # noqa: BLE001
                self.fail(f"{type(exc).__name__}: {exc} on {data.hex()}")
            self.assertGreaterEqual(len(reply), 12, data.hex())
            self.assertTrue(struct.unpack("!H", reply[2:4])[0] & 0x8000,
                            f"QR clear on {data.hex()}")
            self.assertEqual(reply[:2], data[:2], data.hex())
            if budget is not None:
                # The bound the UDP path promises. Over it, the kernel or the
                # path MTU decides what the guest receives, and a silently
                # clipped answer is one it cannot know is clipped.
                self.assertLessEqual(len(reply), budget, data.hex())


class TestLogging(unittest.TestCase):
    """Every decision is journalled, because that is the visibility this rung buys.

    A guest that cannot reach something asks a name first, and the answer it got
    is the difference between "the allowlist refused it" and "the name was
    synthesised to a listener that does not serve that port" -- which look
    identical from inside the guest.
    """

    def test_the_name_type_and_source_are_logged(self):
        mod = _module()
        policy = _policy(mod, static={"git.local": ["192.0.2.9"]})
        mod.build_answer(query("git.local", TYPE_A), policy)
        mod.build_answer(query("elsewhere.example", TYPE_AAAA), policy)
        self.assertEqual(len(mod.logged), 2, mod.logged)
        self.assertIn("git.local", mod.logged[0])
        self.assertIn("A", mod.logged[0])
        self.assertIn("static", mod.logged[0])
        self.assertIn("elsewhere.example", mod.logged[1])
        self.assertIn("AAAA", mod.logged[1])
        self.assertIn("synthesised", mod.logged[1])


class TestSocketActivation(unittest.TestCase):
    """It takes its sockets from the unit and never binds one."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _module()

    def test_a_missing_activation_environment_is_refused(self):
        import unittest.mock
        with unittest.mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(self.mod.NotSocketActivated) as caught:
                self.mod.inherited_listening_sockets()
        self.assertIn("LISTEN_PID", str(caught.exception))

    def test_an_activation_environment_for_another_process_is_refused(self):
        """LISTEN_PID naming another process means the fds are not ours. Without
        the check the program accepts on whatever fd 3 happens to be."""
        import os
        import unittest.mock
        env = {"LISTEN_PID": str(os.getpid() + 1), "LISTEN_FDS": "2"}
        with unittest.mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(self.mod.NotSocketActivated):
                self.mod.inherited_listening_sockets()

    def test_a_non_integer_fd_count_is_refused(self):
        import os
        import unittest.mock
        env = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "two"}
        with unittest.mock.patch.dict("os.environ", env, clear=True):
            with self.assertRaises(self.mod.NotSocketActivated):
                self.mod.inherited_listening_sockets()


class TestGeneratedUnits(unittest.TestCase):
    """The socket and service the generator emits."""

    @classmethod
    def setUpClass(cls):
        from tests import load_script
        cls.gen = load_script("generators/workload-generate")
        config = {"workload": {"name": "web"}, "vm": {"network": {}}}
        cls.socket_unit = cls.gen.generate_vm_resolve_socket(
            config, "_wl-web", UID)
        cls.service = cls.gen.generate_vm_resolve_service(config, "_wl-web")
        cls.address = vm_resolve_address(UID)

    def test_both_transports_are_bound(self):
        """UDP alone leaves a client that opened TCP for its own reasons
        hanging, with nothing to diagnose from."""
        self.assertIn(f"ListenDatagram={self.address}:{VM_RESOLVE_PORT}",
                      self.socket_unit.splitlines())
        self.assertIn(f"ListenStream={self.address}:{VM_RESOLVE_PORT}",
                      self.socket_unit.splitlines())

    def test_the_socket_has_no_address_add(self):
        """The difference from the inspector's socket, and the trap this unit
        of work names. All of 127/8 is local on `lo`, so a `/32` add would be a
        no-op that a later reader takes for load-bearing -- and it would invent
        an address whose absence the inspector's fail-at-bind argument would
        then appear to depend on."""
        self.assertNotIn("ExecStartPre", self.socket_unit)
        self.assertNotIn("ip addr add", self.socket_unit)
        self.assertNotIn("ExecStopPost", self.socket_unit)

    def test_the_socket_does_not_freebind(self):
        self.assertNotIn("FreeBind", self.socket_unit)

    def test_the_trigger_limit_is_set_explicitly(self):
        """Accept=no silently lowers the default to 20 per 2s and hitting it
        fails the socket PERMANENTLY. A guest boot is a burst of lookups."""
        self.assertIn("Accept=no", self.socket_unit.splitlines())
        self.assertIn("TriggerLimitBurst=200", self.socket_unit.splitlines())
        self.assertIn("TriggerLimitIntervalSec=2s", self.socket_unit.splitlines())

    def test_the_socket_stops_with_the_vm(self):
        self.assertIn("PartOf=workload-web.service", self.socket_unit.splitlines())
        self.assertIn("Before=workload-web.service", self.socket_unit.splitlines())

    def test_the_service_runs_as_the_workload_user(self):
        self.assertIn("User=_wl-web", self.service.splitlines())
        self.assertIn("Group=_wl-web", self.service.splitlines())

    def test_the_service_execs_the_responder_with_the_name(self):
        self.assertIn(f'ExecStart={VM_RESOLVE_LISTENER_BIN} "web"',
                      self.service.splitlines())

    def test_the_service_carries_no_cgroup_exemptions(self):
        """The inspector's two exemptions exist because it ORIGINATES traffic.
        The responder originates none -- it has no upstream socket at all --
        so an exemption here would be a hole with nothing behind it."""
        self.assertNotIn("wl_inspect_cg", self.service)
        self.assertNotIn("wl_egress_cg", self.service)
        self.assertNotIn("nft", self.service)

    def test_the_service_stops_with_the_vm(self):
        """PartOf=, so an edited config applies on a plain restart rather than
        the previous run's document being served alongside the new VM."""
        self.assertIn("PartOf=workload-web.service", self.service.splitlines())

    def test_the_slice_is_pinned(self):
        self.assertIn(f"Slice={VM_SIDECAR_SLICE}", self.service.splitlines())

    def test_the_vm_requires_the_responder_socket(self):
        """Requires=, not Wants=. The guest has exactly one nameserver, so a VM
        booted with its responder socket unbound resolves nothing at all while
        looking healthy."""
        config = {"workload": {"name": "web"},
                  "vm": {"memory": "1G", "network": {}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", UID, [])
        self.assertIn("workload-web-resolve.socket", vm_unit)

    def test_resolver_none_pulls_in_no_responder(self):
        """One knob, one meaning. A VM told to ask nobody must not be handed a
        hard prerequisite on a nameserver -- the unit is not generated for it,
        so a Requires= would fail its start on a missing file."""
        config = {"workload": {"name": "web"},
                  "vm": {"memory": "1G", "network": {"resolver": "none"}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", UID, [])
        self.assertNotIn("workload-web-resolve.socket", vm_unit)

    def test_open_egress_pulls_in_no_responder(self):
        config = {"workload": {"name": "web"},
                  "vm": {"memory": "1G", "network": {"egress": "open"}}}
        vm_unit = self.gen.generate_vm_service(config, "_wl-web", UID, [])
        self.assertNotIn("workload-web-resolve.socket", vm_unit)


class TestDnsCounters(unittest.TestCase):
    """The responder's figures, and the one that is not a health metric.

    `unlisted` is the tunnelling signature. Synthesis makes the channel ABSENT
    rather than filtered -- an encoded name is answered like any other and
    resolves nowhere -- so a rising count is evidence that something in the
    guest is trying, never evidence that anything left.
    """

    def setUp(self):
        self.mod = _module()
        self.policy = _policy(self.mod, hosts=["allowed.example", "*.ok.example"])
        self.counters = self.mod.Counters()

    def answer(self, *args, **kwargs):
        return self.mod.build_answer(query(*args, **kwargs), self.policy,
                                     counters=self.counters)

    def test_a_synthesised_answer_is_counted_as_one(self):
        self.answer("allowed.example", TYPE_A)
        self.assertEqual(self.counters.snapshot()["queries"]["synthesised"], 1)

    def test_a_query_for_an_unlisted_name_is_counted_as_unlisted(self):
        self.answer("encoded-data-1.attacker.example", TYPE_A)
        snap = self.counters.snapshot()
        self.assertEqual(snap["unlisted"], 1)
        self.assertIn("encoded-data-1.attacker.example", snap["unlisted_names"])

    def test_it_is_still_answered_and_answered_the_same_way(self):
        """The count must not become a refusal. A responder that withheld an
        answer for an unlisted name would be a different design -- and would
        tell the guest which names are on the list."""
        listed = Reply(self.answer("allowed.example", TYPE_A))
        unlisted = Reply(self.answer("nowhere.example", TYPE_A))
        self.assertEqual(listed.rcode, unlisted.rcode)
        self.assertEqual(listed.addresses(), unlisted.addresses())

    def test_an_allowlisted_name_is_not_counted_as_unlisted(self):
        self.answer("allowed.example", TYPE_A)
        self.assertEqual(self.counters.snapshot()["unlisted"], 0)

    def test_a_wildcard_match_is_on_a_list(self):
        self.answer("api.ok.example", TYPE_A)
        self.assertEqual(self.counters.snapshot()["unlisted"], 0)

    def test_an_allow_entry_counts_as_a_list(self):
        """`static` is an authorisation. A query for one is not the tunnelling
        signature even though `hosts` does not match it."""
        policy = _policy(self.mod, hosts=[],
                         static={"forge.internal": ["10.0.0.5"]})
        self.mod.build_answer(query("forge.internal", TYPE_A), policy,
                              counters=self.counters)
        snap = self.counters.snapshot()
        self.assertEqual(snap["unlisted"], 0)
        self.assertEqual(snap["queries"]["static"], 1)

    def test_a_nodata_type_is_counted_as_nodata_and_not_as_unlisted(self):
        """An HTTPS query names a host the guest is about to look up properly
        anyway. Counting it as unlisted too would double every ordinary miss
        and drown the signal."""
        self.answer("nowhere.example", 65)
        snap = self.counters.snapshot()
        self.assertEqual(snap["queries"]["nodata"], 1)
        self.assertEqual(snap["unlisted"], 0)

    def test_the_unlisted_name_map_is_bounded(self):
        """This is the map a name-encoding guest is actively trying to fill,
        which makes it the one that must not grow."""
        for i in range(200):
            self.answer(f"h{i}.attacker.example", TYPE_A)
        snap = self.counters.snapshot()
        self.assertLessEqual(len(snap["unlisted_names"]), 21)
        self.assertEqual(snap["unlisted"], 200)

    def test_counters_are_optional_and_the_bytes_do_not_change(self):
        """Every existing caller passes none. A response must never be shaped
        by whether anyone is counting."""
        with_counters = self.answer("allowed.example", TYPE_A)
        without = self.mod.build_answer(query("allowed.example", TYPE_A),
                                        self.policy)
        self.assertEqual(with_counters, without)

    def test_a_policy_without_hosts_still_loads(self):
        """A policy document written before this key existed is a policy with
        no host patterns, not a broken one."""
        doc = vm_resolve_policy({}, UID)
        doc.pop("hosts", None)
        policy = self.mod.Policy(doc)
        self.assertEqual(policy.hosts, ())


class TestResponderStatusFile(unittest.TestCase):

    def setUp(self):
        self.mod = _module()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.dir))
        self.path = os.path.join(self.dir, "resolve-status.json")

    def test_it_writes_the_counters(self):
        counters = self.mod.Counters()
        counters.record_answer("a.example", "synthesised", 1, True)
        self.mod.emit_status(self.path, counters)
        doc = json.loads(Path(self.path).read_text())
        self.assertEqual(doc["queries"]["synthesised"], 1)
        self.assertIn("written_at", doc)

    def test_an_unwritable_path_never_takes_the_responder_down(self):
        """A responder that died over a diagnostic would leave the guest
        unable to resolve anything -- a far worse failure than a missing
        file."""
        counters = self.mod.Counters()
        self.mod.emit_status(os.path.join(self.dir, "no", "such", "s.json"),
                             counters)   # must not raise

    def test_an_unserialisable_counter_never_takes_the_responder_down(self):
        """json.dump raises TypeError, not OSError. The except clause has to be
        as wide as the docstring's promise, or a counter added in a later rung
        that is not a plain int costs the guest its DNS rather than costing a
        status file."""
        counters = self.mod.Counters()
        counters.snapshot = lambda: {"a_later_rungs_counter": object()}
        self.mod.emit_status(self.path, counters)   # must not raise
        self.assertFalse(Path(self.path).exists())

    def test_the_loop_writes_before_the_first_query(self):
        """Absence must mean 'never started', not the ambiguous 'never asked a
        question' -- a responder whose guest has looked nothing up is
        healthy, and a socket unit that failed is not.

        The file's existence AFTER serve() returns proves nothing: serve emits
        once more on its way out, so a missing pre-loop write would leave the
        same file behind and the test would pass over the bug. What has to be
        observed is the file existing at the moment the loop first asks whether
        to stop -- which is after the pre-loop emit and before any query."""
        counters = self.mod.Counters()
        seen = []

        def stop():
            seen.append(Path(self.path).exists())
            return True

        self.mod.serve([], self.mod.Policy(vm_resolve_policy({}, UID)),
                       counters, self.path, stop=stop)
        self.assertEqual(seen, [True],
                         "the status file did not exist before the first turn "
                         "of the accept loop")


if __name__ == "__main__":
    unittest.main()
