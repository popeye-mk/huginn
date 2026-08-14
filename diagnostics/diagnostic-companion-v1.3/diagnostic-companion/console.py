"""Console output safety (spec §14.2).

§14.2 forbids emoji in terminal output because Windows consoles and
legacy SSH terminals mangle them. The same reasoning applies to every
non-ASCII character, and the codebase quietly broke its own rule: KB
text and report copy are full of em-dashes, arrows and typographic
quotes. On a real Windows console those render as mojibake — an em-dash
came out as "â€"" on the first Windows run.

**A console and a pipe want different things**, and conflating them is
how the first attempt at this made things worse.

*Writing to a console:* the terminal decodes using its own codepage,
which we cannot change from inside the process. Python already picks
the matching encoding, so the right move is to leave it alone and
transliterate anything that encoding cannot represent. An earlier
version force-reconfigured stdout to UTF-8 here — which made
`sys.stdout.encoding` report "utf-8", so the transliteration check
below concluded everything was encodable and stopped doing its job,
while cmd.exe carried on rendering those UTF-8 bytes as cp1252
mojibake. Forcing UTF-8 disabled the very safety net meant to catch it.

*Writing to a pipe or file:* there is no console in the path. The bytes
are going into a file, a browser, or another program, and UTF-8 is the
correct interchange encoding — especially for HTML, which declares
`charset=utf-8` in its own header. Here we do force UTF-8, because
Python would otherwise pick the locale codepage and silently produce a
file whose bytes contradict its own declared encoding.

So: transliterate for humans, UTF-8 for machines. `isatty()` decides.

A diagnostic tool that garbles its own output undermines the thing it
is selling. Being readable on a bad terminal is worth more than
typographic niceness.
"""

import sys

# Characters that appear in KB text and report copy, mapped to ASCII
# that carries the same meaning. Deliberately not a general Unicode
# normalisation: this is a small, reviewed table of things we actually
# emit, so nothing surprising can slip through.
TRANSLITERATIONS = {
    "—": " - ",   # em dash
    "–": "-",     # en dash
    "‘": "'",     # left single quote
    "’": "'",     # right single quote / apostrophe
    "“": '"',     # left double quote
    "”": '"',     # right double quote
    "…": "...",   # ellipsis
    "→": "->",    # rightwards arrow
    " ": " ",     # non-breaking space
    "•": "*",     # bullet
    "·": "-",     # middle dot
    "×": "x",     # multiplication sign
    "✓": "OK",    # check mark
    "⚠": "!",     # warning sign
}


def is_console(stream=None):
    """True if the stream is an interactive terminal rather than a pipe."""
    stream = stream if stream is not None else sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        # Detached or replaced stream: assume not a console, since the
        # redirected case is the one where getting the encoding wrong
        # corrupts a file rather than merely looking ugly.
        return False


def configure_output():
    """Force UTF-8 only when output is redirected. Never raises.

    Deliberately does nothing for a console: see the module docstring
    for why forcing UTF-8 there both fails to help and actively breaks
    the transliteration fallback.
    """
    for stream in (sys.stdout, sys.stderr):
        if is_console(stream):
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            # Detached, closed, or refuses re-encoding. Transliteration
            # still applies, so this is not fatal.
            pass


def transliterate(text):
    """Replace known non-ASCII characters with ASCII equivalents."""
    for char, replacement in TRANSLITERATIONS.items():
        text = text.replace(char, replacement)
    return text


def encodable(text, encoding):
    """True if `encoding` can represent `text`.

    A stream with no declared encoding (io.StringIO, a captured buffer)
    holds `str` natively and can represent anything — treating that as
    "cannot encode" would needlessly downgrade output in tests and in
    any in-memory pipeline.
    """
    if encoding is None:
        return True
    if not encoding:
        return False
    try:
        text.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def safe_for_stream(text, stream=None):
    """Return `text` unchanged if the stream can encode it, else ASCII-safe.

    Checked rather than assumed: a UTF-8 stream keeps the nicer
    typography, and only a stream that genuinely cannot represent a
    character pays the cost of transliteration.
    """
    stream = stream if stream is not None else sys.stdout
    encoding = getattr(stream, "encoding", None)

    if encodable(text, encoding):
        return text

    downgraded = transliterate(text)
    if encodable(downgraded, encoding):
        return downgraded

    # Something outside the table. Drop to strict ASCII rather than
    # letting the write raise partway through a report.
    return downgraded.encode("ascii", "replace").decode("ascii")


def write(text, stream=None):
    """print() that cannot fail on encoding."""
    stream = stream if stream is not None else sys.stdout
    print(safe_for_stream(text, stream), file=stream)
