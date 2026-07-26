"""Typed systemd unit-file builder.

Correct-by-construction assembly of unit files for the workload generator.
Guarantees that hand-rolled ``lines.append(f"...")`` assembly cannot: a
directive only ever exists inside a section, section headers are always
present, and all newline/blank-line discipline lives in one place
(``Unit.render``).

The builder is deliberately **purely structural**: it never quotes, escapes,
or validates values. Callers pass fully-formed values — already quoted where
systemd needs it (e.g. ``Environment="HOME=..."``) and already joined for a
long ``ExecStart`` command line. The builder decides only layout. This keeps
the emitted text semantically identical to the string concatenation it
replaces; only cosmetic whitespace/comment grouping is owned here.

Layout contract (see ``Unit.render``):
  - optional file-level preamble comments, then the sections in first-seen
    order;
  - exactly one blank line separates each block (preamble and every section);
  - within a section, blank lines and comments appear where the caller placed
    them, except leading/trailing blanks are trimmed (the inter-block
    separator is owned by render, so callers need not balance them);
  - the file ends with exactly one trailing newline.

The ``set()``/``add()`` splice-point invariant
---------------------------------------------
``set()`` collapses to one line per key; ``add()`` appends. Choosing between
them is a correctness decision, not a style one, and the reason is *where* the
user's ``[resources] custom_directives`` land in the file.

``generators/workload-generate`` splices them in early, from
``_resource_overrides()`` — before credentials, exec lines, logging and
hardening. So from that point on, a key the generator is about to emit may
already be present **as the user's line**. The rule:

    after the custom_directives splice, emit with ``add()``, never ``set()``.

``set()`` searches for the key and rewrites that line in place. Post-splice,
the line it finds is the user's, so their value is destroyed and the emitted
unit carries no trace that it was ever supplied. For a repeatable directive
that is outright data loss — a user adding a second ``ExecStartPre=`` gets it
swallowed rather than appended.

**What ``add()`` does and does not buy.** It preserves the user's line, so the
conflict stays visible in the rendered unit and nothing is silently dropped. It
does *not* make the override take effect: both lines are emitted, the
generator's comes later, and systemd's last-wins rule for single-valued
directives therefore picks the **generator's** value. Verified — a workload
setting ``custom_directives = {SyslogIdentifier = "mine"}`` renders
``SyslogIdentifier=mine`` and then ``SyslogIdentifier=workload-<name>``, and
the unit runs with the latter.

**So a default that must actually yield to the user has to opt out at the
source**, by not emitting itself at all:

    if "LogRateLimitIntervalSec" not in custom_d:
        svc.add("LogRateLimitIntervalSec", 30)

``GENERATOR_OWNED_DIRECTIVES`` (``workload_lib``) warns for keys known to be
generator-managed, but it is only a warning list: it neither prevents a later
``set()`` nor covers every managed key.
"""


def _render_line(item):
    """Render one stored line tuple to its text form."""
    kind = item[0]
    if kind == "kv":
        return f"{item[1]}={item[2]}"
    if kind == "comment":
        return ("# " + item[1]).rstrip()
    return ""  # blank


def _strip_edge_blanks(lines):
    """Drop leading and trailing blank-line tuples; keep interior ones."""
    start = 0
    end = len(lines)
    while start < end and lines[start][0] == "blank":
        start += 1
    while end > start and lines[end - 1][0] == "blank":
        end -= 1
    return lines[start:end]


class Section:
    """A ``[Name]`` block: an ordered list of directives, comments, blanks."""

    def __init__(self, name):
        self.name = name
        # each item: ("kv", key, value) | ("comment", text) | ("blank",)
        self._lines = []

    def set(self, key, value):
        """Set a single-valued directive (``Type=``, ``Slice=``, ``User=``).

        If the key was already set in this section its value is updated in
        place; otherwise it is appended. Guarantees at most one line per key.
        """
        text = str(value)
        for i, item in enumerate(self._lines):
            if item[0] == "kv" and item[1] == key:
                self._lines[i] = ("kv", key, text)
                return self
        self._lines.append(("kv", key, text))
        return self

    def add(self, key, value):
        """Append a repeatable directive (``ExecStartPre=``, ``LoadCredentialEncrypted=``).

        Always appends; multiple lines with the same key are preserved in
        order.
        """
        self._lines.append(("kv", key, str(value)))
        return self

    def comment(self, text=""):
        """Append a ``# text`` comment line."""
        self._lines.append(("comment", str(text)))
        return self

    def blank(self):
        """Append a blank line (visual grouping within the section)."""
        self._lines.append(("blank",))
        return self

    def _body(self):
        """Rendered body lines, edge blanks trimmed. Excludes the header."""
        return [_render_line(item) for item in _strip_edge_blanks(self._lines)]


class Unit:
    """A whole unit file: optional preamble comments plus ordered sections."""

    def __init__(self):
        self._preamble = []  # ("comment", text)
        self._sections = {}  # name -> Section, insertion-ordered

    def comment(self, text=""):
        """Append a file-level preamble comment (before the first section)."""
        self._preamble.append(("comment", str(text)))
        return self

    def section(self, name):
        """Return the ``[name]`` section, creating it on first reference.

        Sections render in first-seen order; repeated calls return the same
        object so a caller can add to a section incrementally.
        """
        sec = self._sections.get(name)
        if sec is None:
            sec = Section(name)
            self._sections[name] = sec
        return sec

    def render(self):
        """Serialize to unit-file text (see module docstring for the contract)."""
        blocks = []

        preamble = _strip_edge_blanks(self._preamble)
        if preamble:
            blocks.append([_render_line(item) for item in preamble])

        for sec in self._sections.values():
            blocks.append([f"[{sec.name}]"] + sec._body())

        out = []
        for i, block in enumerate(blocks):
            if i:
                out.append("")  # one blank line between blocks
            out.extend(block)
        return "\n".join(out) + "\n"
