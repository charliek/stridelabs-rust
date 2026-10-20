"""Generate feedparser_decode.json: what feedparser's fetch makes of each
compressed body, the oracle for stridelabs-http's `ssrf-decompress` decoder.

Each case's raw response headers and bytes are served from an in-process
`http.server` on 127.0.0.1 and fetched with `feedparser.http.get`, the
function slaudio's Python pipeline fetches feeds through. The fixture records
the wire bytes, the case's headers, the decoded payload where there is one,
and what feedparser returned: its output bytes, and whether it set `bozo`
(slaudio drops a bozo feed) or raised. Bytes are segment lists (see `enc`);
an output equal to the payload or to the wire bytes says so by name.

Run once, by hand, with slaudio's virtualenv (feedparser 6.0.12, Python
3.13.15), from the repository root:

    ~/projects/slaudio/backend/.venv/bin/python -I \
        crates/http/tests/fixtures/gen_feedparser_decode.py

It is not run in CI. Every byte it serves is built here deterministically
(gzip mtime 0, fixed payloads), so a rerun writes the same file. The
`residue` field is authored, not measured: it names the recorded divergence
(plan 024 section 3.2) a case is expected to show, and the Rust test asserts
exactly that divergence, or exact agreement where it is null.
"""

import gzip
import http.server
import json
import pathlib
import platform
import struct
import sys
import threading
import urllib.request
import zlib

import feedparser
import feedparser.http

OUT = pathlib.Path(__file__).resolve().parent / "feedparser_decode.json"

P = (
    b'<?xml version="1.0" encoding="utf-8"?>\n'
    b'<rss version="2.0"><channel><title>Decode fixture</title>'
    + b"".join(
        b"<item><title>Item %d</title><link>https://feeds.test/%d</link></item>" % (i, i)
        for i in range(24)
    )
    + b"</channel></rss>\n"
)
Q = b"<!-- second member -->" + bytes(range(256)) * 4


def gz(data):
    """One gzip member, as gzip.compress writes it, with mtime 0."""
    return gzip.compress(data, compresslevel=9, mtime=0)


def raw_deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def member(data, *, fname=None, fhcrc=None, extra=None, comment=None, flags=0, method=8, body=None):
    """A gzip member built by hand, for the header fields gzip.compress
    never writes. `fhcrc` is None (no FHCRC), "good" or "bad"; `flags` adds
    raw flag bits (the reserved ones included); `body` replaces the deflate
    data (for a corrupt one)."""
    if extra is not None:
        flags |= 0x04
    if fname is not None:
        flags |= 0x08
    if comment is not None:
        flags |= 0x10
    if fhcrc is not None:
        flags |= 0x02
    header = bytes([0x1F, 0x8B, method, flags]) + struct.pack("<I", 0) + bytes([2, 255])
    if extra is not None:
        header += struct.pack("<H", len(extra)) + extra
    if fname is not None:
        header += fname + b"\0"
    if comment is not None:
        header += comment + b"\0"
    if fhcrc is not None:
        crc16 = zlib.crc32(header) & 0xFFFF
        if fhcrc == "bad":
            crc16 ^= 0xFFFF
        header += struct.pack("<H", crc16)
    trailer = struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)
    return header + (raw_deflate(data) if body is None else body) + trailer


# A stored block producing b"xx", then a block of the reserved type 3: raw
# deflate that writes output before it fails (the review's input, inside a
# gzip member, is this after a ten-byte header).
RAW_OUTPUT_THEN_CORRUPT = bytes.fromhex("000200fdff787807")


def zlib_fails_late_raw_succeeds(n):
    """A raw deflate stream whose first bytes also read as a valid zlib
    header (0x78 0x01) followed by a stored block that zlib decodes for most
    of the body before running out of input: zlib produces substantial output
    and fails, raw decodes the whole stream to 0x01 + b"A" * n."""
    assert n < 65_535
    out = bytes([0x78, 0x01, 0x00, 0xFE, 0xFF, 0x01, 0x00])
    out += struct.pack("<HH", n, n ^ 0xFFFF) + b"A" * n
    out += bytes([0x03, 0x00])  # a final, empty fixed-Huffman block
    assert zlib.decompress(out, -15) == b"\x01" + b"A" * n
    return out


def flip(data, index):
    b = bytearray(data)
    b[index] ^= 0xFF
    return bytes(b)


GZ_P = gz(P)
ZL_P = zlib.compress(P, 9)
RAW_P = raw_deflate(P)
CE = "Content-Encoding"

# (name, response headers, body, decoded payload or None, residue)
CASES = [
    ("no_content_encoding", [], P, P, None),
    ("identity", [(CE, "identity")], P, P, None),
    ("identity_identity", [(CE, "identity, identity")], P, P, None),
    ("gzip_single", [(CE, "gzip")], GZ_P, P, None),
    ("gzip_multi_member", [(CE, "gzip")], GZ_P + gz(Q), P + Q, None),
    ("gzip_zero_padding_between", [(CE, "gzip")], GZ_P + b"\0" * 7 + gz(Q), P + Q, None),
    ("gzip_zero_padding_after", [(CE, "gzip")], GZ_P + b"\0" * 16, P, None),
    ("gzip_zero_padding_before", [(CE, "gzip")], b"\0" * 4 + GZ_P, None, None),
    ("gzip_junk_after", [(CE, "gzip")], GZ_P + b"junk", None, None),
    ("gzip_one_byte_after", [(CE, "gzip")], GZ_P + b"\x01", None, None),
    ("gzip_partial_member_after", [(CE, "gzip")], GZ_P + GZ_P[:6], None, None),
    ("gzip_truncated_body", [(CE, "gzip")], GZ_P[: len(GZ_P) // 2], None, None),
    ("gzip_truncated_trailer", [(CE, "gzip")], GZ_P[:-4], None, None),
    ("gzip_truncated_header", [(CE, "gzip")], GZ_P[:6], None, None),
    ("gzip_bad_trailer_crc", [(CE, "gzip")], flip(GZ_P, len(GZ_P) - 8), None, None),
    ("gzip_bad_isize", [(CE, "gzip")], flip(GZ_P, len(GZ_P) - 1), None, None),
    ("gzip_corrupt_deflate", [(CE, "gzip")], GZ_P[:10] + b"\xff" * 16 + GZ_P[-8:], None, None),
    ("gzip_not_gzip", [(CE, "gzip")], P, None, None),
    ("gzip_empty_member", [(CE, "gzip")], gz(b""), b"", None),
    ("gzip_header_good_fhcrc", [(CE, "gzip")], member(P, fhcrc="good"), P, None),
    ("gzip_header_bad_fhcrc", [(CE, "gzip")], member(P, fhcrc="bad"), P, None),
    ("gzip_fname_65535", [(CE, "gzip")], member(P, fname=b"n" * 65_535), P, None),
    ("gzip_fname_65536", [(CE, "gzip")], member(P, fname=b"n" * 65_536), P, None),
    ("gzip_reserved_flag_0x20", [(CE, "gzip")], member(P, flags=0x20), P, None),
    ("gzip_reserved_flags_0xe0", [(CE, "gzip")], member(P, flags=0xE0), P, None),
    ("gzip_ftext_flag", [(CE, "gzip")], member(P, flags=0x01), P, None),
    ("gzip_fextra", [(CE, "gzip")], member(P, extra=b"ab" * 150), P, None),
    ("gzip_fextra_65535", [(CE, "gzip")], member(P, extra=b"e" * 65_535), P, None),
    ("gzip_fextra_truncated", [(CE, "gzip")], member(P, extra=b"e" * 100)[:60], None, None),
    ("gzip_fcomment_long", [(CE, "gzip")], member(P, comment=b"c" * 100_000), P, None),
    ("gzip_fname_and_fcomment", [(CE, "gzip")], member(P, fname=b"feed.xml", comment=b"hi"), P, None),
    ("gzip_fname_200000", [(CE, "gzip")], member(P, fname=b"n" * 200_000), P, None),
    ("gzip_fname_unterminated", [(CE, "gzip")], member(P, fname=b"n" * 50)[:40], None, None),
    ("gzip_all_header_fields", [(CE, "gzip")], member(P, extra=b"x" * 7, fname=b"f", comment=b"c", fhcrc="bad", flags=0x20), P, None),
    ("gzip_fhcrc_truncated", [(CE, "gzip")], member(P, fhcrc="good")[:11], None, None),
    ("gzip_bad_method", [(CE, "gzip")], member(P, method=7), None, None),
    ("gzip_output_then_corrupt", [(CE, "gzip")], bytes.fromhex("1f8b08000000000000ff000200fdff787807"), None, None),
    ("gzip_member_output_then_corrupt", [(CE, "gzip")], member(b"xx", body=RAW_OUTPUT_THEN_CORRUPT), None, None),
    ("gzip_zero_padding_then_junk", [(CE, "gzip")], GZ_P + b"\0" * 5 + b"junk", None, None),
    ("gzip_zero_padding_then_member", [(CE, "gzip")], GZ_P + b"\0" * 70_000 + gz(Q), P + Q, None),
    ("gzip_lone_magic_byte_after", [(CE, "gzip")], GZ_P + b"\x1f", None, None),
    ("x_gzip", [(CE, "x-gzip")], GZ_P, P, None),
    ("gzip_upper_case", [(CE, "GZIP")], GZ_P, P, "case"),
    ("deflate_upper_case", [(CE, "DEFLATE")], ZL_P, P, "case"),
    ("deflate_zlib", [(CE, "deflate")], ZL_P, P, None),
    ("deflate_raw", [(CE, "deflate")], RAW_P, P, None),
    ("deflate_zlib_trailing_junk", [(CE, "deflate")], ZL_P + b"junk", P, None),
    ("deflate_raw_trailing_junk", [(CE, "deflate")], RAW_P + b"junk", P, None),
    ("deflate_zlib_truncated", [(CE, "deflate")], ZL_P[:-6], None, None),
    ("deflate_raw_truncated", [(CE, "deflate")], RAW_P[: len(RAW_P) // 2], None, None),
    ("deflate_zlib_bad_adler", [(CE, "deflate")], flip(ZL_P, len(ZL_P) - 1), None, None),
    ("deflate_not_deflate", [(CE, "deflate")], P, None, None),
    ("deflate_zlib_output_then_corrupt", [(CE, "deflate")], b"\x78\x01" + RAW_OUTPUT_THEN_CORRUPT, None, None),
    ("deflate_raw_output_then_corrupt", [(CE, "deflate")], RAW_OUTPUT_THEN_CORRUPT, None, None),
    (
        "deflate_zlib_fails_late_raw_succeeds",
        [(CE, "deflate")],
        zlib_fails_late_raw_succeeds(4000),
        b"\x01" + b"A" * 4000,
        None,
    ),
    ("deflate_empty_stream", [(CE, "deflate")], zlib.compress(b""), b"", None),
    ("empty_body_gzip", [(CE, "gzip")], b"", b"", None),
    ("empty_body_deflate", [(CE, "deflate")], b"", b"", None),
    ("identity_then_gzip_one_header", [(CE, "identity, gzip")], GZ_P, P, None),
    ("gzip_then_identity_one_header", [(CE, "gzip, identity")], GZ_P, P, None),
    ("identity_header_then_gzip_header", [(CE, "identity"), (CE, "gzip")], GZ_P, P, None),
    ("gzip_header_then_identity_header", [(CE, "gzip"), (CE, "identity")], GZ_P, P, "last-header"),
    ("stacked_gzip_gzip", [(CE, "gzip, gzip")], gz(GZ_P), None, "stacked-or-unknown"),
    ("stacked_deflate_gzip", [(CE, "deflate, gzip")], gz(ZL_P), None, "stacked-or-unknown"),
    ("br", [(CE, "br")], b"\x1b\x00\xf8\xa5\x7f\x00", None, "stacked-or-unknown"),
    ("zstd", [(CE, "zstd")], b"\x28\xb5\x2f\xfd\x00\x00", None, "stacked-or-unknown"),
]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        name = self.path.lstrip("/")
        headers, body = SERVED[name]
        self.send_response(200)
        self.send_header("Content-Type", "application/rss+xml")
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


SERVED = {}


def enc(data):
    """Bytes as a list of segments: a hex string, or `[byte, count]` for a
    run of at least 32 equal bytes (the 64 KiB FNAMEs would otherwise be most
    of the file)."""
    segments, i = [], 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] == data[i]:
            j += 1
        if j - i >= 32:
            segments.append([data[i], j - i])
            i = j
            continue
        start = i
        while i < len(data):
            j = i
            while j < len(data) and data[j] == data[i]:
                j += 1
            if j - i >= 32:
                break
            i = j
        segments.append(data[start:i].hex())
    return segments


def body_ref(data, wire, payload):
    """feedparser's output: "payload" or "wire" when it is one of those
    byte for byte, else its segments."""
    if payload is not None and data == payload:
        return "payload"
    if data == wire:
        return "wire"
    return enc(data)


def fetch(base, name, wire, payload):
    result = {}
    try:
        # An empty ProxyHandler: no proxy from the environment reaches this.
        data = feedparser.http.get(
            f"{base}/{name}", result=result, handlers=[urllib.request.ProxyHandler({})]
        )
    except Exception as e:  # what feedparser.parse would turn into a bozo
        return {"outcome": "raised", "exception": type(e).__name__}
    if result.get("bozo"):
        return {
            "outcome": "bozo",
            "exception": type(result.get("bozo_exception")).__name__,
            "body": None if data is None else body_ref(data, wire, payload),
        }
    return {"outcome": "ok", "body": body_ref(data, wire, payload)}


def main():
    for name, headers, body, _, _ in CASES:
        assert name not in SERVED, name
        SERVED[name] = (headers, body)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    cases = []
    try:
        for name, headers, body, payload, residue in CASES:
            cases.append(
                {
                    "name": name,
                    "headers": [[k, v] for k, v in headers],
                    "wire": enc(body),
                    "payload": None if payload is None else enc(payload),
                    "residue": residue,
                    "python": fetch(base, name, body, payload),
                }
            )
    finally:
        server.shutdown()
    fixture = {
        "provenance": {
            "generator": "crates/http/tests/fixtures/gen_feedparser_decode.py",
            "feedparser": feedparser.__version__,
            "python": platform.python_version(),
            "function": "feedparser.http.get",
        },
        "cases": cases,
    }
    OUT.write_text(json.dumps(fixture, indent=1) + "\n")
    print(f"wrote {len(cases)} cases to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
