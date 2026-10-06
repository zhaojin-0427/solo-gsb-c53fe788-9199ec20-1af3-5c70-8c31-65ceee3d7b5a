"""End-to-end tests: hand-crafted (damaged) ZIPs through the HTTP API."""

from __future__ import annotations

import binascii
import hashlib
import io
import os
import struct
import subprocess
import sys
import warnings
import zipfile
import zlib

import pytest
from fastapi.testclient import TestClient

from app.main import Settings, create_app

# ---------------------------------------------------------------------
# ZIP building blocks
# ---------------------------------------------------------------------

def crc32(b: bytes) -> int:
    return binascii.crc32(b) & 0xFFFFFFFF


def lfh(name: bytes, method: int, flags: int, crc: int, csize: int,
        usize: int, extra: bytes = b"") -> bytes:
    return struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, method, 0, 0,
        crc, csize, usize, len(name), len(extra),
    ) + name + extra


def dd_sig(crc: int, csize: int, usize: int) -> bytes:
    return struct.pack("<IIII", 0x08074B50, crc, csize, usize)


def dd_nosig(crc: int, csize: int, usize: int) -> bytes:
    return struct.pack("<III", crc, csize, usize)


def cd_entry(name: bytes, method: int, flags: int, crc: int, csize: int,
             usize: int, offset: int) -> bytes:
    return struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, 0, 0,
        crc, csize, usize, len(name), 0, 0, 0, 0, 0, offset,
    ) + name


def eocd(count: int, cd_size: int, cd_offset: int) -> bytes:
    return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count,
                       cd_size, cd_offset, 0)


def deflate_raw(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def stored_entry(name: bytes, data: bytes, offset: int = 0) -> bytes:
    return lfh(name, 0, 0, crc32(data), len(data), len(data)) + data


def make_central(parts: list) -> bytes:
    """parts: list of (name, method, flags, crc, csize, usize, offset)"""
    cd = b"".join(cd_entry(*p) for p in parts)
    return cd + eocd(len(parts), len(cd), 0)


# ---------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path):
    app = create_app(Settings(data_dir=str(tmp_path / "data")))
    with TestClient(app) as c:
        yield c


def post(client, blob: bytes, **kwargs):
    return client.post("/recover", content=blob, **kwargs)


# ---------------------------------------------------------------------
# healthy archives
# ---------------------------------------------------------------------

def test_healthy_zipfile_archive(client):
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate-name warning
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("hello.txt", b"hello world\n",
                       compress_type=zipfile.ZIP_DEFLATED)
            z.writestr("hello.txt", b"hello world, again\n",
                       compress_type=zipfile.ZIP_DEFLATED)
            z.writestr("raw.bin", b"\x00\x01\x02" * 100,
                       compress_type=zipfile.ZIP_STORED)
    r = post(client, buf.getvalue(), params={"filename": "healthy.zip"})
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["summary"]["total_entries"] == 3
    assert rep["summary"]["confirmed"] == 3
    assert rep["summary"]["candidate"] == 0
    assert rep["damaged_ranges"] == []
    assert rep["central_directory"]["status"] == "present"
    # duplicate names keep their sequence numbers
    assert rep["entries"][0]["name"] == "hello.txt"
    assert rep["entries"][0]["name_seq"] == 1
    assert rep["entries"][1]["name"] == "hello.txt"
    assert rep["entries"][1]["name_seq"] == 2
    # downloads return the original bytes
    job = rep["id"]
    d0 = client.get(f"/recover/{job}/entries/0")
    assert d0.status_code == 200
    assert d0.content == b"hello world\n"
    assert d0.headers["X-Entry-SHA256"] == hashlib.sha256(
        b"hello world\n").hexdigest()
    d1 = client.get(f"/recover/{job}/entries/1")
    assert d1.content == b"hello world, again\n"
    d2 = client.get(f"/recover/{job}/entries/2")
    assert d2.content == b"\x00\x01\x02" * 100
    # report is persisted and retrievable
    again = client.get(f"/recover/{job}")
    assert again.status_code == 200
    assert again.json() == rep
    listed = client.get("/recover").json()["jobs"]
    assert [j["id"] for j in listed] == [job]


def test_central_directory_removed(client):
    a = stored_entry(b"a.txt", b"alpha-data")
    b = stored_entry(b"b.txt", b"beta-data" * 10)
    blob = a + b  # no central directory, no EOCD
    r = post(client, blob)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["central_directory"]["status"] == "missing"
    assert [e["status"] for e in rep["entries"]] == ["confirmed", "confirmed"]
    assert rep["entries"][0]["name"] == "a.txt"
    assert rep["entries"][1]["name"] == "b.txt"
    job = rep["id"]
    assert client.get(f"/recover/{job}/entries/1").content == b"beta-data" * 10


def test_central_directory_truncated(client):
    a = stored_entry(b"a.txt", b"alpha-data")
    b = stored_entry(b"b.txt", b"beta-data")
    cd = cd_entry(b"a.txt", 0, 0, crc32(b"alpha-data"), 10, 10, 0)
    blob = a + b + cd[:20]  # CD starts but is cut off
    r = post(client, blob)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["central_directory"]["status"] == "truncated"
    assert [e["status"] for e in rep["entries"]] == ["confirmed", "confirmed"]


# ---------------------------------------------------------------------
# data descriptors
# ---------------------------------------------------------------------

def test_deflate_with_signed_descriptor(client):
    data = b"deflate me please " * 50
    comp = deflate_raw(data)
    arc = (lfh(b"d.bin", 8, 0x08, 0, 0, 0)
           + comp + dd_sig(crc32(data), len(comp), len(data)))
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    e = rep["entries"][0]
    assert e["status"] == "confirmed"
    assert e["descriptor"] == "signature"
    assert e["size"] == len(data)
    assert e["compressed_size"] == len(comp)
    assert client.get(
        f"/recover/{rep['id']}/entries/0").content == data


def test_deflate_with_unsigned_descriptor(client):
    data = b"unsigned descriptor payload " * 30
    comp = deflate_raw(data)
    crc = crc32(data)
    assert crc != 0x08074B50  # would collide with the DD signature
    arc = (lfh(b"d.bin", 8, 0x08, 0, 0, 0)
           + comp + dd_nosig(crc, len(comp), len(data)))
    r = post(client, arc)
    assert r.status_code == 201, r.text
    e = r.json()["entries"][0]
    assert e["status"] == "confirmed"
    assert e["descriptor"] == "nosignature"
    assert client.get(
        f"/recover/{r.json()['id']}/entries/0").content == data


def test_stored_with_signed_descriptor_unknown_length(client):
    data = b"stored bytes with a signed descriptor"
    arc = (lfh(b"s.bin", 0, 0x08, 0, 0, 0)
           + data + dd_sig(crc32(data), len(data), len(data))
           + eocd(1, 0, 0))  # EOCD announces a CD that is not there
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    e = rep["entries"][0]
    assert e["status"] == "confirmed"
    assert e["descriptor"] == "signature"
    assert e["size"] == len(data)
    assert rep["central_directory"]["status"] == "missing"
    assert rep["central_directory"]["eocd_offset"] is not None
    assert client.get(
        f"/recover/{rep['id']}/entries/0").content == data


def test_stored_with_unsigned_descriptor_unknown_length(client):
    data = b"stored bytes with an unsigned descriptor"
    nxt = stored_entry(b"next.txt", b"next")
    arc = (lfh(b"s.bin", 0, 0x08, 0, 0, 0)
           + data + dd_nosig(crc32(data), len(data), len(data)) + nxt)
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert [e["status"] for e in rep["entries"]] == ["confirmed", "confirmed"]
    assert rep["entries"][0]["descriptor"] == "nosignature"
    assert client.get(
        f"/recover/{rep['id']}/entries/0").content == data
    assert client.get(f"/recover/{rep['id']}/entries/1").content == b"next"


# ---------------------------------------------------------------------
# damage, resynchronisation, fake headers
# ---------------------------------------------------------------------

def test_corruption_marks_following_entries_candidate(client):
    a = stored_entry(b"a.txt", b"A" * 40)
    b_data = bytearray(b"B" * 60)
    b = stored_entry(b"b.txt", bytes(b_data))
    c = stored_entry(b"c.txt", b"C" * 30)
    blob = bytearray(a + b + c)
    # corrupt the middle of b's data (keep the header intact)
    pos = len(a) + 30 + 6 + 10
    blob[pos:pos + 8] = b"\xde\xad\xbe\xef" * 2
    r = post(client, bytes(blob))
    assert r.status_code == 201, r.text
    rep = r.json()
    assert [e["name"] for e in rep["entries"]] == ["a.txt", "c.txt"]
    assert rep["entries"][0]["status"] == "confirmed"
    assert rep["entries"][1]["status"] == "candidate"
    assert len(rep["damaged_ranges"]) == 1
    dr = rep["damaged_ranges"][0]
    assert dr["offset"] == len(a)
    assert dr["offset"] + dr["length"] == len(a) + len(b)
    # candidate bytes are still downloadable
    job = rep["id"]
    assert client.get(f"/recover/{job}/entries/1").content == b"C" * 30


def test_fake_header_inside_data_is_not_trusted(client):
    a = stored_entry(b"a.txt", b"A" * 20)
    garbage = b"\x00" * 10
    fake = lfh(b"fake.txt", 0, 0, 0xDEADBEEF, 4, 4) + b"zzzz"
    assert crc32(b"zzzz") != 0xDEADBEEF
    c = stored_entry(b"c.txt", b"real-data")
    blob = a + garbage + fake + c
    r = post(client, blob)
    assert r.status_code == 201, r.text
    rep = r.json()
    names = [e["name"] for e in rep["entries"]]
    assert names == ["a.txt", "c.txt"]  # the fake header is skipped
    assert rep["entries"][1]["status"] == "candidate"
    assert len(rep["damaged_ranges"]) == 1
    dr = rep["damaged_ranges"][0]
    assert dr["offset"] == len(a)
    assert dr["length"] == len(garbage) + len(fake)


def test_ambiguous_stored_splits_are_reported(client):
    # split 1: unsigned DD right before a real entry -> entry = c1
    c1 = b"hello, "
    dd1 = dd_nosig(crc32(c1), len(c1), len(c1))
    inner = stored_entry(b"inner.txt", b"inner-data")
    # split 2: signed DD swallowing dd1+inner into the same entry
    region = c1 + dd1 + inner
    dd2 = dd_sig(crc32(region), len(region), len(region))
    arc = lfh(b"ambig.bin", 0, 0x08, 0, 0, 0) + region + dd2
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    e0 = rep["entries"][0]
    # two verifiable layouts -> ambiguity, and the chain is broken
    assert len(e0["ambiguity"]) == 2
    assert e0["status"] == "candidate"
    assert rep["entries"][1]["name"] == "inner.txt"
    assert rep["entries"][1]["status"] == "candidate"
    assert rep["summary"]["ambiguous"] == 1
    # the walk followed the smallest split with a valid continuation
    assert e0["end_offset"] == rep["entries"][1]["offset"]
    assert client.get(f"/recover/{rep['id']}/entries/0").content == c1


def test_deflate_csize_mismatch_uses_stream_boundary(client):
    data = b"stream boundary wins " * 20
    comp = deflate_raw(data)
    junk = b"\x07" * 5
    nxt = stored_entry(b"n.txt", b"next-entry")
    arc = (lfh(b"d.bin", 8, 0, crc32(data), len(comp) + 5, len(data))
           + comp + junk + nxt)
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    e0 = rep["entries"][0]
    assert e0["status"] == "confirmed"
    assert e0["compressed_size"] == len(comp)
    assert any("stream boundary" in n for n in e0["notes"])
    # the 5 junk bytes are reported as damaged, the next entry is candidate
    assert rep["damaged_ranges"][0]["length"] == 5
    assert rep["entries"][1]["status"] == "candidate"
    assert client.get(f"/recover/{rep['id']}/entries/0").content == data


def test_truncated_archive_reports_damage_to_eof(client):
    a = stored_entry(b"a.txt", b"A" * 10)
    data = b"B" * 100
    b = lfh(b"b.txt", 0, 0, crc32(data), len(data), len(data)) + data[:40]
    r = post(client, a + b)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert [e["name"] for e in rep["entries"]] == ["a.txt"]
    assert rep["damaged_ranges"][0]["offset"] == len(a)
    assert rep["damaged_ranges"][0]["length"] == len(b)


# ---------------------------------------------------------------------
# whole-order rejections (no partial artifacts)
# ---------------------------------------------------------------------

def test_encrypted_entry_rejected(client, tmp_path):
    arc = lfh(b"secret.txt", 0, 0x01, 0, 0, 0) + b"\x00" * 12
    r = post(client, arc)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "encrypted"
    assert client.get("/recover").json()["jobs"] == []
    assert list((tmp_path / "data" / "jobs").iterdir()) == []


def test_zip64_entry_rejected(client):
    arc = lfh(b"big.bin", 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"\x00" * 8
    r = post(client, arc)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "zip64"
    assert client.get("/recover").json()["jobs"] == []


def test_zip64_extra_field_rejected(client):
    extra = struct.pack("<HH", 0x0001, 0)  # ZIP64 extra, empty payload
    arc = lfh(b"big.bin", 0, 0, 0, 0, 0, extra=extra)
    r = post(client, arc)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "zip64"


def test_expand_limit_rejected(tmp_path):
    app = create_app(Settings(data_dir=str(tmp_path / "data"),
                              max_expand_bytes=1024))
    with TestClient(app) as c:
        data = b"A" * 5000  # expands well past 1 KiB
        arc = lfh(b"bomb.bin", 8, 0, crc32(data), 0, len(data)) \
            + deflate_raw(data)
        r = post(c, arc)
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "expand_limit_exceeded"
        assert c.get("/recover").json()["jobs"] == []
        assert list((tmp_path / "data" / "jobs").iterdir()) == []


def test_upload_limit_rejected(tmp_path):
    app = create_app(Settings(data_dir=str(tmp_path / "data"),
                              max_upload_bytes=100))
    with TestClient(app) as c:
        r = post(c, b"\x00" * 200)
        assert r.status_code == 413
        assert r.json()["detail"]["error"] == "upload_too_large"


def test_unknown_job_and_entry(client):
    assert client.get("/recover/nope").status_code == 404
    arc = stored_entry(b"a.txt", b"A" * 4)
    job = post(client, arc).json()["id"]
    assert client.get(f"/recover/{job}/entries/7").status_code == 404


def test_empty_upload(client):
    r = post(client, b"")
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["summary"]["total_entries"] == 0
    assert rep["entries"] == []


# ---------------------------------------------------------------------
# high-ratio DEFLATE: bounded decompression memory
# ---------------------------------------------------------------------

def zeros_deflated(size: int) -> tuple:
    """(crc32, sha256, compressed) for ``size`` zero bytes, built in
    1 MiB blocks so the test process never materialises the payload."""
    block = b"\x00" * (1024 * 1024)
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    parts, crc, sha = [], 0, hashlib.sha256()
    left = size
    while left:
        b = block[: min(left, len(block))]
        parts.append(c.compress(b))
        crc = binascii.crc32(b, crc)
        sha.update(b)
        left -= len(b)
    parts.append(c.flush())
    return crc, sha.hexdigest(), b"".join(parts)


def test_high_ratio_deflate_recovers_within_limit(client):
    """A small archive holding a highly-compressed member recovers fine
    as long as the cumulative expansion stays within the limit."""
    size = 64 * 1024 * 1024  # 64 MiB expansion, ~64 KiB compressed
    crc, sha, comp = zeros_deflated(size)
    arc = lfh(b"zeros.bin", 8, 0, crc, len(comp), size) + comp
    assert len(arc) < 1024 * 1024  # the upload itself stays tiny
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    e = rep["entries"][0]
    assert e["status"] == "confirmed"
    assert e["size"] == size
    assert e["compressed_size"] == len(comp)
    assert e["crc32"] == f"{crc:08x}"
    assert e["sha256"] == sha
    assert rep["summary"]["expanded_bytes"] == size
    d = client.get(f"/recover/{rep['id']}/entries/0")
    assert d.status_code == 200
    assert len(d.content) == size
    assert hashlib.sha256(d.content).hexdigest() == sha


def test_high_ratio_deflate_with_descriptors(client):
    """Bit-3 entries: the consumed-byte count must locate the data
    descriptor exactly, even when output capping splits the stream."""
    size1, size2 = 20 * 1024 * 1024, 15 * 1024 * 1024
    crc1, sha1, comp1 = zeros_deflated(size1)
    crc2, sha2, comp2 = zeros_deflated(size2)
    e1 = (lfh(b"big1.bin", 8, 0x08, 0, 0, 0)
          + comp1 + dd_sig(crc1, len(comp1), size1))
    e2 = (lfh(b"big2.bin", 8, 0x08, 0, 0, 0)
          + comp2 + dd_nosig(crc2, len(comp2), size2))
    tail = stored_entry(b"tail.txt", b"tail")
    arc = e1 + e2 + tail
    r = post(client, arc)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert [e["status"] for e in rep["entries"]] == ["confirmed"] * 3
    e0, e1r, e2r = rep["entries"]
    assert e0["descriptor"] == "signature"
    assert e1r["descriptor"] == "nosignature"
    assert e0["compressed_size"] == len(comp1)
    assert e1r["compressed_size"] == len(comp2)
    # descriptor offsets are exact: entries butt up against each other
    assert e0["end_offset"] == e1r["offset"]
    assert e1r["end_offset"] == e2r["offset"]
    job = rep["id"]
    d0 = client.get(f"/recover/{job}/entries/0")
    d1 = client.get(f"/recover/{job}/entries/1")
    assert hashlib.sha256(d0.content).hexdigest() == sha1
    assert hashlib.sha256(d1.content).hexdigest() == sha2
    assert client.get(f"/recover/{job}/entries/2").content == b"tail"


def test_single_decompress_output_is_bounded(client, monkeypatch):
    """One decompress() call never returns more than MAX_OUT bytes, so
    a single compressed block cannot allocate an unbounded buffer."""
    import app.recover as rec

    real_factory = zlib.decompressobj
    seen = []

    class Spy:
        def __init__(self, inner):
            self._inner = inner

        def decompress(self, data, max_length=0):
            out = self._inner.decompress(data, max_length)
            seen.append(len(out))
            return out

        def __getattr__(self, name):
            return getattr(self._inner, name)

    monkeypatch.setattr(
        rec.zlib, "decompressobj",
        lambda *a, **k: Spy(real_factory(*a, **k)),
    )
    size = 32 * 1024 * 1024
    crc, _sha, comp = zeros_deflated(size)
    arc = lfh(b"zeros.bin", 8, 0, crc, len(comp), size) + comp
    r = post(client, arc)
    assert r.status_code == 201, r.text
    assert seen, "decompress was never called"
    assert max(seen) <= rec.MAX_OUT


def test_high_ratio_expand_limit_rejected(tmp_path):
    """Tiny upload whose cumulative expansion exceeds the limit:
    422 expand_limit_exceeded, no job, no leftover temp files."""
    limit = 32 * 1024 * 1024
    app = create_app(Settings(data_dir=str(tmp_path / "data"),
                              max_expand_bytes=limit))
    with TestClient(app) as c:
        size = 40 * 1024 * 1024  # expands past the 32 MiB limit
        crc, _sha, comp = zeros_deflated(size)
        arc = lfh(b"bomb.bin", 8, 0, crc, 0, size) + comp
        assert len(arc) < 1024 * 1024
        r = post(c, arc)
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "expand_limit_exceeded"
        assert c.get("/recover").json()["jobs"] == []
        assert list((tmp_path / "data" / "jobs").iterdir()) == []
        assert list((tmp_path / "data" / "tmp").iterdir()) == []


def test_high_ratio_recovery_fits_container_memory(tmp_path):
    """Recovery of a 600 MiB expansion must work within the 512 MiB
    container memory limit (verified in an RLIMIT_AS-capped child)."""
    size = 600 * 1024 * 1024
    crc, sha, comp = zeros_deflated(size)
    zip_path = tmp_path / "hiratio.zip"
    zip_path.write_bytes(
        lfh(b"zeros.bin", 8, 0, crc, len(comp), size) + comp)
    workdir = tmp_path / "work"
    workdir.mkdir()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script = (
        "import resource, sys\n"
        "resource.setrlimit(resource.RLIMIT_AS, (512 << 20, -1))\n"
        f"sys.path.insert(0, {root!r})\n"
        "from app.recover import run_recovery\n"
        f"rep = run_recovery({str(zip_path)!r}, {str(workdir)!r}, 1 << 30)\n"
        "e = rep['entries'][0]\n"
        "print(e['size'], e['sha256'], rep['summary']['expanded_bytes'])\n"
    )
    out = subprocess.run([sys.executable, "-c", script],
                         capture_output=True, text=True, timeout=600)
    assert out.returncode == 0, out.stderr
    got_size, got_sha, got_expanded = out.stdout.split()
    assert int(got_size) == size
    assert got_sha == sha
    assert int(got_expanded) == size
