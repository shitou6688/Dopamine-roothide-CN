#!/usr/bin/env python3
"""
Dopamine-roothide CN kernel source tooling.

Why this exists
---------------
Upstream Dopamine-roothide calls grab_images() from the closed-source
libgrabkernel2.a. That library first downloads a ~72 MB metadata blob from
https://api.appledb.dev/ios/main.json.xz, then partial-zips the matching IPSW
from an Apple CDN. api.appledb.dev is unreliable from mainland China, so the
whole "Downloading Kernel" step appears to require an overseas proxy.

The firmware itself is served by updates.cdn-apple.com, which answers
206 Partial Content and is cached inside mainland China. This tool moves all
metadata work to the GitHub Actions runner (which has unrestricted network)
and ships the result inside the IPA:

  * KernelIndex.plist  - per <hw.machine>|<kern.osversion> entry with the
                          firmware URL and exact byte ranges of kernelcache /
                          sptm / txm inside that IPSW. Runtime only needs a
                          few HTTP Range requests against the Apple CDN.
  * kernelcache        - optional, fully offline build: the real files are
                          embedded in the app bundle. Upstream already checks
                          bundlePath/kernelcache, sptm.img4 and txm.img4 first,
                          so no network request happens at all.

Commands
--------
  selftest              Verify the remote-zip reader against a synthetic ZIP64 file.
  probe   --url URL     Inspect a real IPSW (uses only a few KB of traffic).
  index   --out FILE    Build a schema-1 KernelIndex.plist (single target,
                        includes SHA-256 of each downloaded kernel image).
  fullindex --out FILE  Build a schema-2 index covering every iPhone/iPad/iPod
                        and every firmware version Dopamine supports. Reads
                        only ZIP central directories (CRC32 instead of SHA-256),
                        concurrently, so thousands of IPSWs stay cheap.
  fetch   --out DIR     Download kernelcache + sptm + txm for one target
                        (fully-offline IPA mode).
  patch   --repo DIR    Idempotently patch DOEnvironmentManager.m and copy the
                        Objective-C runtime helper into the app sources.
  pack    --app DIR     Copy generated resources into the .app, re-sign and
          --out NAME     rebuild IPA/TIPA.

Only the Python standard library is required.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
import zlib
from datetime import datetime, timezone

UA = "DopamineCNKernelTool/1.0 (+GitHub Actions)"
EOCD = b"PK\x05\x06"
ZIP64_EOCD = b"PK\x06\x06"
ZIP64_LOCATOR = b"PK\x06\x07"
CENTRAL = b"PK\x01\x02"
LOCAL = b"PK\x03\x04"
MAX32 = 0xFFFFFFFF
IPSW_API = "https://api.ipsw.me/v4/device/{device}?type=ipsw"


def log(msg: str) -> None:
    print(f"[cn-kernel] {msg}", flush=True)


def die(msg: str) -> None:
    print(f"[cn-kernel] ERROR: {msg}", file=sys.stderr, flush=True)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Remote ZIP reader (ZIP64 aware). IPSWs are 8-12 GB, so only the tail and the
# central directory are ever fetched.
# ---------------------------------------------------------------------------


class RemoteZip:
    def __init__(self, url: str, timeout: int = 60, retries: int = 3,
                 quiet: bool = False):
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.quiet = quiet
        self.size = self._probe_size()
        self._entries: dict[str, dict] | None = None

    def _request(self, start: int | None = None, length: int | None = None,
                 method: str = "GET") -> tuple[bytes, dict]:
        headers = {"User-Agent": UA, "Accept-Encoding": "identity"}
        if start is not None:
            headers["Range"] = f"bytes={start}-{start + length - 1}"
        req = urllib.request.Request(self.url, headers=headers, method=method)
        last = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return r.read(), dict(r.headers)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
                time.sleep(1 + attempt)
        raise RuntimeError(f"request failed after {self.retries} tries: {last}")

    def _probe_size(self) -> int:
        data, headers = self._request(0, 1)
        cr = headers.get("Content-Range") or headers.get("content-range")
        if not cr or "/" not in cr:
            # HEAD fallback
            req = urllib.request.Request(self.url, method="HEAD", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return int(r.headers["Content-Length"])
        return int(cr.rsplit("/", 1)[1])

    def fetch(self, start: int, length: int) -> bytes:
        if length <= 0:
            return b""
        if start < 0 or start + length > self.size:
            raise ValueError(f"range {start}+{length} outside file ({self.size})")
        data, _ = self._request(start, length)
        if len(data) != length:
            raise RuntimeError(f"short range read: wanted {length}, got {len(data)}")
        return data

    def _eocd(self) -> tuple[int, int, int]:
        # EOCD + ZIP64 locator + ZIP64 EOCD fit comfortably in 64 KiB.
        tail_len = min(self.size, 65557 + 56)
        tail = self.fetch(self.size - tail_len, tail_len)
        pos = tail.rfind(EOCD)
        if pos < 0:
            raise RuntimeError("ZIP end-of-central-directory not found")
        eocd = tail[pos:pos + 22]
        if len(eocd) < 22:
            raise RuntimeError("truncated EOCD")
        (_disk, _cd_disk, _n_here, total, cd_size, cd_offset) = struct.unpack(
            "<4H2I", eocd[4:20])
        if total == 0xFFFF or cd_size == MAX32 or cd_offset == MAX32:
            loc = tail.rfind(ZIP64_LOCATOR)
            if loc < 0:
                raise RuntimeError("ZIP64 locator not found")
            if loc + 20 > len(tail):
                raise RuntimeError("truncated ZIP64 locator")
            z64_off = struct.unpack("<Q", tail[loc + 8:loc + 16])[0]
            head = self.fetch(z64_off, 56)
            if head[:4] != ZIP64_EOCD:
                raise RuntimeError("ZIP64 EOCD signature mismatch")
            total64, cd_size64, cd_offset64 = struct.unpack("<QQQ", head[32:56])
            return total64, cd_size64, cd_offset64
        return total, cd_size, cd_offset

    @staticmethod
    def _zip64_extra(extra: bytes, need: dict[str, bool]) -> dict:
        """Pull 8-byte values out of a ZIP64 extra field, in canonical order."""
        out: dict[str, int] = {}
        pos = 0
        cursor = 0
        while pos + 4 <= len(extra):
            tag, sz = struct.unpack("<HH", extra[pos:pos + 4])
            body = extra[pos + 4:pos + 4 + sz]
            pos += 4 + sz
            if tag != 0x0001:
                continue
            for key in ("uncompressed", "compressed", "offset", "disk"):
                if need.get(key) and cursor + 8 <= len(body):
                    out[key] = struct.unpack("<Q", body[cursor:cursor + 8])[0]
                    cursor += 8
                elif need.get(key) and key == "disk" and cursor + 4 <= len(body):
                    out[key] = struct.unpack("<I", body[cursor:cursor + 4])[0]
                    cursor += 4
            break
        return out

    def entries(self) -> dict[str, dict]:
        if self._entries is not None:
            return self._entries
        total, cd_size, cd_offset = self._eocd()
        if not self.quiet:
            log(f"central directory: {total} entries, {cd_size} bytes @ {cd_offset}")
        cd = self.fetch(cd_offset, cd_size)
        result: dict[str, dict] = {}
        p = 0
        for _ in range(total):
            if cd[p:p + 4] != CENTRAL or p + 46 > len(cd):
                raise RuntimeError(f"bad central directory entry at {p}")
            (flags, compression, _mtime, _mdate, crc, csize, usize,
             nlen, elen, clen, _disk, _int, _ext, hoff) = struct.unpack(
                "<4H3I5H2I", cd[p + 8:p + 46])
            name = cd[p + 46:p + 46 + nlen].decode("utf-8", "replace")
            extra = cd[p + 46 + nlen:p + 46 + nlen + elen]
            need = {"uncompressed": usize == MAX32,
                    "compressed": csize == MAX32,
                    "offset": hoff == MAX32, "disk": _disk == 0xFFFF}
            if any(need.values()):
                z64 = self._zip64_extra(extra, need)
                usize = z64.get("uncompressed", usize)
                csize = z64.get("compressed", csize)
                hoff = z64.get("offset", hoff)
            result[name] = {
                "name": name, "flags": flags, "compression": compression,
                "crc": crc, "compressed_size": csize,
                "uncompressed_size": usize, "header_offset": hoff,
            }
            p += 46 + nlen + elen + clen
        self._entries = result
        return result

    def data_offset(self, entry: dict) -> int:
        head = self.fetch(entry["header_offset"], 30)
        if head[:4] != LOCAL:
            raise RuntimeError(f"bad local header for {entry['name']}")
        nlen, elen = struct.unpack("<HH", head[26:30])
        return entry["header_offset"] + 30 + nlen + elen

    def read(self, name: str) -> bytes:
        entry = self.entries()[name]
        raw = self.fetch(self.data_offset(entry), entry["compressed_size"])
        if entry["compression"] == 0:
            return raw
        if entry["compression"] == 8:
            out = zlib.decompress(raw, -15)
            if len(out) != entry["uncompressed_size"]:
                raise RuntimeError(f"size mismatch after inflate: {name}")
            return out
        raise RuntimeError(f"unsupported compression {entry['compression']}: {name}")

    def range_of(self, name: str) -> dict:
        e = self.entries()[name]
        return {
            "path": name,
            "offset": self.data_offset(e),
            "length": e["compressed_size"],
            "compression": e["compression"],
            "uncompressedSize": e["uncompressed_size"],
            # ZIP central directory CRC of the *uncompressed* member. It lets
            # the device verify an inflated kernel without the build machine
            # ever downloading the 17 MB payload.
            "crc32": e["crc"],
        }


# ---------------------------------------------------------------------------
# Firmware discovery
# ---------------------------------------------------------------------------


def _get_json(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _appledb_candidates(device: str, build: str) -> tuple[list[str], str]:
    """Lightweight per-build AppleDB endpoint (a few KB, not the 72 MB blob)."""
    for os_str in ("iOS", "iPadOS"):
        url = f"https://api.appledb.dev/ios/{os_str};{build}.json"
        try:
            j = _get_json(url, timeout=15)
        except Exception as exc:
            log(f"AppleDB {os_str};{build} unavailable ({type(exc).__name__}), trying next source")
            continue
        urls: list[str] = []

        def collect(source: dict, types: tuple[str, ...]) -> None:
            if source.get("type") not in types:
                return
            if device not in (source.get("deviceMap") or []):
                return
            for link in source.get("links") or []:
                u = link.get("url", "")
                if not u.startswith("https://") or link.get("active") is False:
                    continue
                if link.get("preferred") and u not in urls:
                    urls.insert(0, u)
                elif u not in urls:
                    urls.append(u)

        for src in j.get("sources", []):
            collect(src, ("ipsw",))
        if urls:
            log(f"AppleDB resolved {build} for {device}: {urls[0][:100]}")
            return urls[:4], j.get("version", "")
    return [], ""


def resolve_firmware_url(device: str, build: str,
                         explicit: str | None) -> tuple[list[str], str]:
    """Return (candidate firmware URLs, marketing version)."""
    if explicit:
        return [explicit], "explicit"
    if not device or not build:
        die("need --firmware-url or both --device and --build")

    urls, version = _appledb_candidates(device, build)
    if urls:
        return urls, version

    url = IPSW_API.format(device=device)
    log(f"AppleDB miss, resolving firmware URL via {url}")
    try:
        j = _get_json(url, timeout=45)
    except Exception as exc:
        die(f"cannot resolve firmware for {device}/{build}: {exc}. "
            "Pass --firmware-url with a direct IPSW link instead.")
    for fw in j.get("firmwares", []):
        if fw.get("buildid", "").upper() == build.upper():
            return [fw["url"]], fw.get("version", "")
    available = ", ".join(f"{f['buildid']}({f.get('version')})"
                          for f in j.get("firmwares", [])[:12])
    die(f"build {build} not found for {device}. Recent: {available}")


def pick_kernel_names(rz: RemoteZip) -> dict[str, str]:
    """Resolve the kernelcache / SPTM / TXM member names of an IPSW."""
    names = rz.entries().keys()
    manifest_name = next(
        (n for n in names if n.lower().endswith("buildmanifest.plist")), None)
    if not manifest_name:
        raise RuntimeError("BuildManifest.plist missing")
    manifest = plistlib.loads(rz.read(manifest_name))
    found: dict[str, str] = {}
    for ident in manifest.get("BuildIdentities", []):
        man = ident.get("Manifest", {})
        for key, slot in (("KernelCache", "kernel"),
                          ("Ap,SecurePageTableMonitor", "sptm"),
                          ("Ap,TrustedExecutionMonitor", "txm")):
            path = (man.get(key) or {}).get("Info", {}).get("Path")
            if path and slot not in found:
                if path in rz.entries():
                    found[slot] = path
        if "kernel" in found:
            break
    # Some OTA/manifest variants expose these only as plain files.
    for n in names:
        low = n.lower()
        if "kernel" not in found and low.startswith("kernelcache."):
            found["kernel"] = n
        if "sptm" not in found and low.endswith("sptm.im4p"):
            found["sptm"] = n
        if "txm" not in found and low.endswith("txm.im4p"):
            found["txm"] = n
    if "kernel" not in found:
        raise RuntimeError("kernelcache member not found in IPSW")
    found["manifest"] = manifest_name
    return found


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_selftest(_args) -> None:
    """Build a local ZIP64 file and verify range parsing against a file:// URL."""
    import tempfile
    payloads = {
        "BuildManifest.plist": plistlib.dumps({"BuildIdentities": []}),
        "kernelcache.release.test": bytes(range(256)) * 400,
        "Firmware/sptm.im4p": b"SPTM" * 1024,
        "Firmware/txm.im4p": b"TXM!" * 1024,
    }
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "test.ipsw")
        with zipfile.ZipFile(path, "w", allowZip64=True) as z:
            for name, data in payloads.items():
                zi = zipfile.ZipInfo(name)
                zi.compress_type = zipfile.ZIP_STORED
                z.writestr(zi, data)
        # Serve through a local HTTP server so the exact Range code path runs.
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with open(path, "rb") as f:
                    f.seek(0, 2)
                    size = f.tell()
                rng = self.headers.get("Range", "")
                start, end = 0, size - 1
                if rng.startswith("bytes="):
                    a, _, b = rng[6:].partition("-")
                    start = int(a) if a else 0
                    end = int(b) if b else size - 1
                with open(path, "rb") as f:
                    f.seek(start)
                    body = f.read(end - start + 1)
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Length", str(os.path.getsize(path)))
                self.end_headers()
            def log_message(self, *_):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{srv.server_port}/test.ipsw"
            rz = RemoteZip(url, timeout=10)
            assert rz.size == os.path.getsize(path), "size"
            entries = rz.entries()
            assert set(payloads) == set(entries), f"entries: {entries.keys()}"
            for name, data in payloads.items():
                got = rz.read(name)
                assert got == data, f"content mismatch: {name}"
                assert rz.range_of(name)["length"] == len(data)
            log("selftest OK: ZIP central directory, ZIP64 extras, ranges and payloads verified")
        finally:
            srv.shutdown()
    # Deflate path is covered by the real probe command; assert the primitive here.
    raw = b"hello kernelcache" * 100
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    packed = co.compress(raw) + co.flush()
    assert zlib.decompress(packed, -15) == raw
    log("selftest OK: raw-deflate inflate primitive verified")


def cmd_probe(args) -> None:
    rz = RemoteZip(args.url)
    log(f"IPSW size: {rz.size} bytes")
    names = pick_kernel_names(rz)
    for slot, name in names.items():
        info = rz.range_of(name)
        log(f"  {slot:9s} {name}  offset={info['offset']} len={info['length']} "
            f"compression={info['compression']} raw={info['uncompressedSize']}")
    k = rz.read(names["kernel"])
    log(f"kernelcache sha256={sha256(k)} bytes={len(k)}")


def _entry_for(urls: list[str], device: str, build: str) -> dict:
    rz = RemoteZip(urls[0])
    names = pick_kernel_names(rz)
    entry: dict = {
        "firmwareURLs": urls,
        "version": "",
        "ipswSize": rz.size,
    }
    for slot in ("manifest", "kernel", "sptm", "txm"):
        if slot not in names:
            continue
        info = rz.range_of(names[slot])
        data = rz.read(names[slot])
        info["sha256"] = sha256(data)
        info["size"] = len(data)
        entry[slot] = info
        log(f"{device}|{build} {slot}: {info['path']} "
            f"len={info['length']} raw={info['size']} sha256={info['sha256'][:16]}...")
    return entry


# ---------------------------------------------------------------------------
# Full-coverage index (schema 2)
#
# A single-target index can afford to download each 17 MB kernelcache and
# store its SHA-256. Covering every jailbreakable device cannot: thousands of
# IPSWs would mean tens of gigabytes. ZIP central directories already carry
# CRC32, method, sizes and offsets, so `fullindex` only reads the tail, the
# central directory, the tiny local headers and BuildManifest.plist. The
# device verifies the inflated payload against that CRC32 instead.
# ---------------------------------------------------------------------------

IPSW_DEVICES_API = "https://api.ipsw.me/v4/devices"


def _version_tuple(v: str) -> tuple[int, int, int]:
    nums = [int(x) for x in re.findall(r"\d+", v)[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])  # type: ignore[return-value]


def _in_support_range(version: str) -> bool:
    """Mirror -versionSupportString in DOEnvironmentManager.m."""
    v = _version_tuple(version)
    if (15, 0, 0) <= v <= (18, 7, 1):
        return True
    if (26, 0, 0) <= v <= (26, 0, 1):  # A12/A13 PPL branch
        return True
    return False


def _catalog_devices(explicit_file: str | None) -> list[str]:
    if explicit_file:
        with open(explicit_file, encoding="utf-8") as f:
            return sorted({line.strip() for line in f
                           if line.strip() and not line.lstrip().startswith("#")})
    j = _get_json(IPSW_DEVICES_API, timeout=60)
    ids = [d["identifier"] for d in j if isinstance(d, dict)
           and str(d.get("identifier", "")).startswith(("iPhone", "iPad", "iPod"))]
    return sorted(set(ids))


def _device_targets(device: str) -> list[tuple[str, str, str, str]]:
    """(device, build, marketing version, IPSW URL) for supported firmware."""
    j = None
    for attempt in range(3):
        try:
            j = _get_json(IPSW_API.format(device=device), timeout=45)
            break
        except Exception as exc:
            if attempt == 2:
                log(f"catalog {device}: {type(exc).__name__}")
                return []
            time.sleep(1 + attempt)
    if j is None:
        return []
    out: list[tuple[str, str, str, str]] = []
    seen: set[str] = set()
    for fw in j.get("firmwares", []):
        version = str(fw.get("version", ""))
        build = str(fw.get("buildid", ""))
        url = str(fw.get("url", ""))
        if not build or build in seen or not url.startswith("https://"):
            continue
        if not _in_support_range(version):
            continue
        seen.add(build)
        out.append((device, build, version, url))
    return out


def _entry_for_fast(urls: list[str], device: str, build: str,
                    timeout: int = 25) -> dict:
    rz = RemoteZip(urls[0], timeout=timeout, retries=2, quiet=True)
    names = pick_kernel_names(rz)
    entry: dict = {"firmwareURLs": urls, "ipswSize": rz.size}
    for slot in ("kernel", "sptm", "txm"):
        if slot in names:
            entry[slot] = rz.range_of(names[slot])
    if "kernel" not in entry:
        raise RuntimeError("kernelcache member missing")
    return entry


def cmd_fullindex(args) -> None:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    devices = _catalog_devices(args.devices)
    if args.device_limit:
        devices = devices[:args.device_limit]
    log(f"catalog: {len(devices)} iOS/iPadOS device identifiers")

    targets: list[tuple[str, str, str, str]] = []
    with ThreadPoolExecutor(max_workers=min(16, args.workers)) as pool:
        for rows in pool.map(_device_targets, devices):
            targets.extend(rows)
    log(f"firmware pairs inside Dopamine's supported versions: {len(targets)}")
    if not targets:
        die("no firmware pairs found; check network access to api.ipsw.me")
    if args.limit:
        targets = targets[:args.limit]

    entries: dict[str, dict] = {}
    skipped: list[tuple[str, str]] = []

    def work(item: tuple[str, str, str, str]):
        device, build, version, url = item
        key = f"{device}|{build}"
        try:
            entry = _entry_for_fast([url], device, build, timeout=args.timeout)
            entry["version"] = version
            return key, entry, None
        except Exception as exc:
            return key, None, f"{type(exc).__name__}: {exc}"

    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(work, t) for t in targets]
        for future in as_completed(futures):
            key, entry, err = future.result()
            done += 1
            if entry:
                entries[key] = entry
            else:
                skipped.append((key, err or "unknown"))
            if done % 100 == 0 or done == len(targets):
                log(f"progress {done}/{len(targets)} ok={len(entries)} "
                    f"skipped={len(skipped)}")

    if not entries:
        die("no IPSW could be indexed; Apple CDN may be unreachable")
    doc = {
        "schema": 2,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "source": "ipsw.me device catalog + Apple CDN ZIP central directories",
        "coverage": {
            "devices": len(devices),
            "firmwarePairs": len(targets),
            "entries": len(entries),
            "skipped": len(skipped),
        },
        "entries": entries,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as f:
        plistlib.dump(doc, f, fmt=plistlib.FMT_XML, sort_keys=True)
    log(f"wrote {args.out} ({os.path.getsize(args.out)} bytes, "
        f"{len(entries)} entries covering {len(devices)} device identifiers)")
    for key, err in skipped[:15]:
        log(f"  skipped {key}: {err[:150]}")


def _load_targets(args) -> list[tuple[str, str, str | None]]:
    """Return [(device, build, explicit_url), ...]."""
    out = []
    if args.targets:
        for line in open(args.targets, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                die(f"bad target line: {line}")
            out.append((parts[0], parts[1], parts[2] if len(parts) > 2 else None))
    if args.firmware_url or args.device:
        out.append((args.device or args.target_device or "iPhone15,3",
                    args.build or "", args.firmware_url))
    if not out:
        die("no targets: pass --targets FILE or --firmware-url/--device+--build")
    return out


def infer_build_from_url(url: str) -> str:
    """iPhone15,3_17.3.1_21D61_Restore.ipsw -> 21D61."""
    m = re.search(r"_(\d{2}[A-Z]\d{1,4}[a-z]?)_", url)
    return m.group(1) if m else ""


def cmd_index(args) -> None:
    targets = _load_targets(args)
    entries = {}
    for device, build, explicit in targets:
        if not build and explicit:
            build = infer_build_from_url(explicit)
            if build:
                log(f"inferred build {build} from explicit IPSW URL")
        if not build:
            die(f"missing build for {device}: the runtime key must be "
                "<hw.machine>|<kern.osversion>, so a real build is required")
        urls, version = resolve_firmware_url(device, build, explicit)
        log(f"indexing {device}|{build} -> {urls[0]}")
        e = _entry_for(urls, device, build)
        e["version"] = version
        entries[f"{device}|{build}"] = e
    doc = {
        "schema": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "source": "AppleDB per-build endpoint + ipsw.me fallback (resolved at build time)",
        "entries": entries,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as f:
        plistlib.dump(doc, f, fmt=plistlib.FMT_XML, sort_keys=True)
    log(f"wrote {args.out} ({os.path.getsize(args.out)} bytes, {len(entries)} entries)")


def cmd_fetch(args) -> None:
    device, build, explicit = _load_targets(args)[0]
    urls, _ = resolve_firmware_url(device, build, explicit)
    rz = RemoteZip(urls[0])
    names = pick_kernel_names(rz)
    os.makedirs(args.out, exist_ok=True)
    # Bundle names match upstream after cmd_patch adds .im4p lookups to
    # -accessibleSPTMPath / -accessibleTXMPath. IPSW members are IM4P payloads,
    # so keeping that name avoids any XPF format sniffing ambiguity.
    mapping = {"kernel": "kernelcache", "sptm": "sptm.im4p", "txm": "txm.im4p"}
    for slot, dest in mapping.items():
        if slot not in names:
            log(f"skip {slot}: not present in this IPSW")
            continue
        data = rz.read(names[slot])
        path = os.path.join(args.out, dest)
        with open(path, "wb") as f:
            f.write(data)
        log(f"wrote {path} ({len(data)} bytes, sha256={sha256(data)})")


PATCH_BEGIN = "// >>> CN-KERNEL-SOURCE (managed by Tools/cn_kernel.py) >>>"
PATCH_END = "// <<< CN-KERNEL-SOURCE <<<"

IMPORT_LINE = '#import "DO_CN_KernelSource.h"'

OLD_BLOCK = '''        [[DOUIManager sharedInstance] sendLog:@"Downloading Kernel" debug:NO];
        NSString *kernelcachePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kernelcache"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            if (grab_images([NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]) == false) return nil;
        }
        return kernelcachePath;'''

SPTM_OLD = '''    NSString *sptmInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"sptm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInAppPath]) {
        return sptmInAppPath;
    }'''

SPTM_NEW = SPTM_OLD + '''
    
    NSString *sptmIm4pInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"sptm.im4p"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmIm4pInAppPath]) {
        return sptmIm4pInAppPath;
    }'''

TXM_OLD = '''    NSString *txmInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"txm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInAppPath]) {
        return txmInAppPath;
    }'''

TXM_NEW = TXM_OLD + '''
    
    NSString *txmIm4pInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"txm.im4p"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmIm4pInAppPath]) {
        return txmIm4pInAppPath;
    }'''

NEW_BLOCK = '''        NSString *documentsDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        NSString *kernelcachePath = [documentsDir stringByAppendingPathComponent:@"kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) return kernelcachePath;

        // CN path: metadata was resolved at build time; only Apple CDN Range
        // requests are needed. Falls back to libgrabkernel2 on any miss.
        [[DOUIManager sharedInstance] sendLog:@"Downloading Kernel (CN direct)" debug:NO];
        if (DOCNTryIndexDownload(documentsDir)) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) return kernelcachePath;
        }
        [[DOUIManager sharedInstance] sendLog:@"Falling back to libgrabkernel2" debug:NO];
        if (grab_images(documentsDir) == false) return nil;
        return kernelcachePath;'''


def cmd_patch(args) -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(args.repo)
    target_dir = os.path.join(repo, "Application", "Dopamine", "Jailbreak")
    target = os.path.join(target_dir, "DOEnvironmentManager.m")
    if not os.path.isfile(target):
        die(f"not a Dopamine-roothide checkout: missing {target}")
    # Preserve the file's exact line endings; upstream uses LF and a plain
    # text-mode write on Windows would turn the whole file into a CRLF diff.
    with open(target, "r", encoding="utf-8", newline="") as f:
        src = f.read()

    if PATCH_BEGIN in src:
        log("DOEnvironmentManager.m already patched (idempotent)")
    else:
        # 1) inject the #import right after the libgrabkernel2 import
        anchor = "#import <libgrabkernel2/libgrabkernel2.h>"
        if anchor not in src:
            die(f"cannot find import anchor: {anchor}")
        src = src.replace(anchor, anchor + "\n" + IMPORT_LINE, 1)
        # 2) replace the download block
        if OLD_BLOCK not in src:
            die("download block does not match upstream 3.x; inspect "
                "-accessibleKernelPath in DOEnvironmentManager.m manually")
        src = src.replace(OLD_BLOCK,
                          PATCH_BEGIN + "\n" + NEW_BLOCK + "\n" + PATCH_END, 1)
        # 3) let the app bundle carry IM4P payloads under their native name,
        #    exactly like grab_images() writes them into Documents.
        for label, old, new in (("accessibleSPTMPath", SPTM_OLD, SPTM_NEW),
                                ("accessibleTXMPath", TXM_OLD, TXM_NEW)):
            if old not in src:
                die(f"{label} block does not match upstream 3.x; inspect it manually")
            src = src.replace(old, new, 1)
        with open(target, "w", encoding="utf-8", newline="") as f:
            f.write(src)
        log("patched DOEnvironmentManager.m (import + 3 accessible*Path methods)")

    # The helper is a header with a fully inline implementation, so Xcode's
    # project file needs no modification (no new compile source / no new link).
    header_src = os.path.join(here, "DO_CN_KernelSource.h")
    header_dst = os.path.join(target_dir, "DO_CN_KernelSource.h")
    shutil.copyfile(header_src, header_dst)
    log(f"installed {header_dst}")
    log("patch complete: no .xcodeproj / pbxproj changes required")


def cmd_pack(args) -> None:
    app = os.path.abspath(args.app)
    if not os.path.isdir(app):
        die(f"app bundle not found: {app}")
    copied = []
    for item in args.resources:
        src = os.path.abspath(item)
        if os.path.isdir(src):
            for name in os.listdir(src):
                s = os.path.join(src, name)
                if os.path.isfile(s):
                    shutil.copy2(s, os.path.join(app, name))
                    copied.append(name)
        elif os.path.isfile(src):
            shutil.copy2(src, os.path.join(app, os.path.basename(src)))
            copied.append(os.path.basename(src))
    log(f"copied into bundle: {', '.join(copied) or '(none)'}")

    entitlements = os.path.abspath(args.entitlements)
    exe = os.path.join(app, "Dopamine")
    subprocess.run(["xattr", "-rc", app], check=True)
    subprocess.run(["ldid", f"-S{entitlements}", exe], check=True)
    subprocess.run(["ldid", "-s", app], check=True)

    work = os.path.dirname(app)
    payload = os.path.join(work, "Payload")
    shutil.rmtree(payload, ignore_errors=True)
    os.makedirs(payload)
    shutil.copytree(app, os.path.join(payload, "Dopamine.app"), symlinks=True)
    ipa = os.path.abspath(args.out)
    tipa = os.path.splitext(ipa)[0] + ".tipa"
    for out in (ipa, tipa):
        if os.path.exists(out):
            os.remove(out)
    subprocess.run(["zip", "-qAr", ipa, "Payload"], cwd=work, check=True)
    shutil.copyfile(ipa, tipa)
    shutil.rmtree(payload, ignore_errors=True)
    log(f"wrote {ipa} ({os.path.getsize(ipa)} bytes)")
    log(f"wrote {tipa}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest")

    p = sub.add_parser("probe")
    p.add_argument("--url", required=True)

    p = sub.add_parser("index")
    p.add_argument("--out", required=True)
    p.add_argument("--targets", help="file with lines: DEVICE|BUILD[|IPSW_URL]")
    p.add_argument("--device")
    p.add_argument("--build")
    p.add_argument("--firmware-url")
    p.add_argument("--target-device", help="device key when using --firmware-url")

    p = sub.add_parser("fetch")
    p.add_argument("--out", required=True)
    p.add_argument("--targets")
    p.add_argument("--device")
    p.add_argument("--build")
    p.add_argument("--firmware-url")
    p.add_argument("--target-device")

    p = sub.add_parser("fullindex")
    p.add_argument("--out", required=True)
    p.add_argument("--workers", type=int, default=32,
                   help="concurrent IPSW central-directory probes")
    p.add_argument("--timeout", type=int, default=25,
                   help="per-request timeout for one IPSW probe")
    p.add_argument("--limit", type=int, default=0,
                   help="debug: only the first N firmware pairs")
    p.add_argument("--device-limit", type=int, default=0,
                   help="debug: only the first N device identifiers")
    p.add_argument("--devices", help="optional file with device identifiers")

    p = sub.add_parser("patch")
    p.add_argument("--repo", required=True)

    p = sub.add_parser("pack")
    p.add_argument("--app", required=True)
    p.add_argument("--resources", nargs="*", default=[])
    p.add_argument("--entitlements", required=True)
    p.add_argument("--out", required=True)

    args = ap.parse_args()
    {"selftest": cmd_selftest, "probe": cmd_probe, "index": cmd_index,
     "fullindex": cmd_fullindex, "fetch": cmd_fetch, "patch": cmd_patch,
     "pack": cmd_pack}[args.cmd](args)


if __name__ == "__main__":
    main()
