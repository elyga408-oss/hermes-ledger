"""Hermes Ledger core: a hash-chained, Ed25519-signed, append-only log.

This module has no Hermes imports on purpose. It needs only the Python standard
library and ``cryptography``, so a third party can verify a ledger or a receipt
without installing Hermes (see ``verify_receipt.py``).

Format (one canonical-JSON record per line, ``ledger.jsonl``)::

    body        = record minus {"seq", "prev_hash", "hash", "sig"}
    body_sha256 = sha256(canonical(body))
    hash        = sha256(canonical({"body_sha256": ..., "prev_hash": ..., "seq": ...}))
    sig         = base64(Ed25519.sign(bytes.fromhex(hash)))

``canonical`` is JSON with sorted keys, no whitespace, ASCII-only escapes.
Splitting the hash into a body digest and a link digest lets a receipt include
*stubs* (seq, prev_hash, body_sha256, hash, sig) for records from other
sessions: the verifier can still recompute every link and check every
signature without seeing those records' contents.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

FORMAT_VERSION = 1
GENESIS_HASH = "0" * 64
RECEIPT_FORMAT = "hermes-ledger-receipt/1"
KINDS = ("tool_call", "tool_result", "approval", "note")

LEDGER_FILE = "ledger.jsonl"
HEAD_FILE = "ledger.head"
LOCK_FILE = "ledger.lock"
PRIVATE_KEY_FILE = "ed25519.key"
PUBLIC_KEY_FILE = "ed25519.pub"

_LINK_FIELDS = ("seq", "prev_hash", "hash", "sig")
_REQUIRED = ("v", "seq", "ts", "session", "kind", "tool", "args_redacted",
             "result_sha256", "prev_hash", "hash", "sig", "key_id")


# --------------------------------------------------------------------------- hashing

def canonical(obj: Any) -> bytes:
    """Canonical JSON bytes: sorted keys, no whitespace, ASCII escapes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False, default=str).encode("ascii")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def body_of(record: dict) -> dict:
    return {k: v for k, v in record.items() if k not in _LINK_FIELDS}


def body_sha256(record: dict) -> str:
    return sha256_hex(canonical(body_of(record)))


def link_hash(seq: int, prev_hash: str, body_digest: str) -> str:
    return sha256_hex(canonical({"body_sha256": body_digest, "prev_hash": prev_hash, "seq": seq}))


def record_hash(record: dict) -> str:
    return link_hash(record["seq"], record["prev_hash"], body_sha256(record))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# --------------------------------------------------------------------------- keys

def key_id_for(public_raw: bytes) -> str:
    return hashlib.sha256(public_raw).hexdigest()[:16]


def public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_public_key(spec: str | bytes | Path) -> Ed25519PublicKey:
    """Accept base64 raw key text, a path to a file holding it, or raw 32 bytes."""
    if isinstance(spec, bytes) and len(spec) == 32:
        return Ed25519PublicKey.from_public_bytes(spec)
    text = spec.decode() if isinstance(spec, bytes) else str(spec)
    candidate = Path(text).expanduser()
    try:
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8")
    except OSError:
        pass
    raw = base64.b64decode(text.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


class KeyPair:
    """The ledger's signing key. The private half never leaves this object."""

    def __init__(self, private: Ed25519PrivateKey):
        self._private = private
        self.public = private.public_key()
        self.public_raw = public_raw(self.public)
        self.public_b64 = base64.b64encode(self.public_raw).decode("ascii")
        self.key_id = key_id_for(self.public_raw)

    def sign_hex(self, digest_hex: str) -> str:
        return base64.b64encode(self._private.sign(bytes.fromhex(digest_hex))).decode("ascii")

    def __repr__(self) -> str:  # never show key material
        return f"KeyPair(key_id={self.key_id})"

    @classmethod
    def load_or_create(cls, directory: Path) -> "KeyPair":
        directory.mkdir(parents=True, exist_ok=True)
        with _suppress_oserror():
            os.chmod(directory, 0o700)
        priv_path = directory / PRIVATE_KEY_FILE
        pub_path = directory / PUBLIC_KEY_FILE
        if not priv_path.exists():
            private = Ed25519PrivateKey.generate()
            pem = private.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            try:
                fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                fd = None  # another process won the race; load theirs below
            if fd is not None:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(pem)
                    fh.flush()
                    os.fsync(fh.fileno())
        with _suppress_oserror():
            os.chmod(priv_path, 0o600)
        private = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError(f"{priv_path} is not an Ed25519 private key")
        pair = cls(private)
        if not pub_path.exists() or pub_path.read_text(encoding="utf-8").strip() != pair.public_b64:
            _atomic_write(pub_path, (pair.public_b64 + "\n").encode("ascii"), mode=0o644)
        return pair


def verify_sig(pub: Ed25519PublicKey, digest_hex: str, sig_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(sig_b64, validate=True), bytes.fromhex(digest_hex))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- file helpers

class _suppress_oserror:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and issubclass(exc_type, OSError)


def _atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class _FileLock:
    """Exclusive inter-process lock on a lock file (flock on POSIX, msvcrt on Windows)."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def __enter__(self):
        self._fh = open(self.path, "a+b")
        try:
            import fcntl
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        except ImportError:  # Windows
            import msvcrt
            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
        return self

    def __exit__(self, *exc):
        try:
            try:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
            except ImportError:
                import msvcrt
                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()
            self._fh = None


def _last_valid_record(path: Path) -> Optional[dict]:
    """Read backwards from the end of the log and return the last parseable record."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return None
    if size == 0:
        return None
    with open(path, "rb") as fh:
        block = 8192
        buf = b""
        pos = size
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            lines = buf.split(b"\n")
            # lines[0] may be partial unless we've reached the start of the file
            candidates = lines if pos == 0 else lines[1:]
            for raw in reversed(candidates):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("seq"), int) and "hash" in rec:
                    return rec
            block *= 2
    return None


# --------------------------------------------------------------------------- the ledger

class Ledger:
    """An append-only, hash-chained, signed log stored in one directory."""

    def __init__(self, directory: Path | str, *, fsync: bool = True):
        self.dir = Path(directory)
        self.path = self.dir / LEDGER_FILE
        self.head_path = self.dir / HEAD_FILE
        self.lock_path = self.dir / LOCK_FILE
        self.fsync = fsync
        self._thread_lock = threading.Lock()
        self._keys: Optional[KeyPair] = None

    # -- keys
    @property
    def keys(self) -> KeyPair:
        if self._keys is None:
            self._keys = KeyPair.load_or_create(self.dir)
        return self._keys

    def public_key_b64(self) -> Optional[str]:
        p = self.dir / PUBLIC_KEY_FILE
        return p.read_text(encoding="utf-8").strip() if p.exists() else None

    # -- writing
    def append(self, kind: str, *, session: str = "", tool: Optional[str] = None,
               args_redacted: Any = None, result_sha256: Optional[str] = None,
               **extra: Any) -> dict:
        """Append one record. Serialised across threads and processes; returns the record."""
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        self.dir.mkdir(parents=True, exist_ok=True)
        with self._thread_lock, _FileLock(self.lock_path):
            keys = self.keys
            last = _last_valid_record(self.path)
            seq = 0 if last is None else int(last["seq"]) + 1
            prev = GENESIS_HASH if last is None else str(last["hash"])
            record: dict[str, Any] = {
                "v": FORMAT_VERSION, "ts": utc_now(), "session": session or "", "kind": kind,
                "tool": tool, "args_redacted": args_redacted, "result_sha256": result_sha256,
                "key_id": keys.key_id,
            }
            for k, v in extra.items():
                if k in _LINK_FIELDS or k in record:
                    raise ValueError(f"field {k!r} is reserved")
                record[k] = v
            record["seq"] = seq
            record["prev_hash"] = prev
            record["hash"] = record_hash(record)
            record["sig"] = keys.sign_hex(record["hash"])
            line = canonical(record) + b"\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line)
                if self.fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)
            head = {"seq": seq, "hash": record["hash"], "key_id": keys.key_id}
            head["sig"] = keys.sign_hex(sha256_hex(canonical(head)))
            if self.fsync:
                _atomic_write(self.head_path, canonical(head) + b"\n", mode=0o600)
            else:
                self.head_path.write_bytes(canonical(head) + b"\n")
            return record

    # -- reading
    def iter_lines(self) -> Iterator[tuple[int, bytes]]:
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for lineno, raw in enumerate(fh, start=1):
                yield lineno, raw

    def records(self) -> list[dict]:
        """Every parseable record, in file order (no verification)."""
        out = []
        for _, raw in self.iter_lines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out

    def read_head(self) -> Optional[dict]:
        try:
            return json.loads(self.head_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def verify(self, pubkey: Optional[str | Path] = None) -> "VerifyResult":
        pub_spec = pubkey or self.public_key_b64()
        if not pub_spec:
            if not self.path.exists() or self.path.stat().st_size == 0:
                return VerifyResult(ok=True, count=0, reason="empty ledger")
            return VerifyResult(ok=False, count=0, broken_seq=0, reason="public key file is missing")
        try:
            pub = load_public_key(pub_spec)
        except Exception as exc:
            return VerifyResult(ok=False, count=0, broken_seq=0, reason=f"unusable public key: {exc}")
        return verify_lines(self.iter_lines(), pub, head=self.read_head(),
                            head_present=self.head_path.exists())


# --------------------------------------------------------------------------- verification

@dataclass
class VerifyResult:
    ok: bool
    count: int
    broken_seq: Optional[int] = None
    line: Optional[int] = None
    reason: str = ""
    last_hash: Optional[str] = None
    key_id: Optional[str] = None
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            tail = f", head {self.last_hash[:12]}" if self.last_hash else ""
            key = f", key {self.key_id}" if self.key_id else ""
            return f"OK: {self.count} records, chain intact{tail}{key}"
        where = f"seq {self.broken_seq}" if self.broken_seq is not None else "unknown entry"
        line = f" (line {self.line})" if self.line else ""
        return f"BROKEN at {where}{line}: {self.reason}"

    def to_dict(self) -> dict:
        return {"ok": self.ok, "count": self.count, "broken_seq": self.broken_seq,
                "line": self.line, "reason": self.reason, "last_hash": self.last_hash,
                "key_id": self.key_id, "warnings": list(self.warnings),
                "summary": self.summary()}


def check_record(rec: Any, pub: Ed25519PublicKey, key_id: str, expected_seq: int,
                 prev_hash: str) -> Optional[str]:
    """Return None when ``rec`` is a valid successor, else the reason it is not."""
    if not isinstance(rec, dict):
        return "line is not a JSON object"
    missing = [f for f in _REQUIRED if f not in rec]
    if missing:
        return f"record is missing field(s): {', '.join(missing)}"
    seq = rec["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool):
        return "seq is not an integer"
    if seq > expected_seq:
        return (f"record seq {expected_seq} is missing (next record found is seq {seq}): "
                "deleted or reordered")
    if seq < expected_seq:
        return f"found seq {seq} where seq {expected_seq} was expected: reordered or duplicated"
    if rec["kind"] not in KINDS:
        return f"unknown kind {rec['kind']!r}"
    if rec["prev_hash"] != prev_hash:
        return "prev_hash does not match the previous record's hash: chain broken"
    if record_hash(rec) != rec["hash"]:
        return "content does not match its hash: record was edited"
    if rec["key_id"] != key_id:
        return f"signed by key {rec['key_id']}, expected key {key_id}"
    if not verify_sig(pub, rec["hash"], rec["sig"]):
        return "signature is not valid for this public key"
    return None


def verify_lines(lines: Iterable[tuple[int, bytes]], pub: Ed25519PublicKey, *,
                 head: Optional[dict] = None, head_present: bool = False) -> VerifyResult:
    key_id = key_id_for(public_raw(pub))
    expected_seq = 0
    prev = GENESIS_HASH
    hashes: dict[int, str] = {}
    for lineno, raw in lines:
        text = raw.strip()
        if not text:
            continue
        try:
            rec = json.loads(text)
        except ValueError:
            return VerifyResult(ok=False, count=expected_seq, broken_seq=expected_seq, line=lineno,
                                reason="line is not valid JSON (edited, or a torn write)",
                                key_id=key_id)
        reason = check_record(rec, pub, key_id, expected_seq, prev)
        if reason:
            return VerifyResult(ok=False, count=expected_seq, broken_seq=expected_seq, line=lineno,
                                reason=reason, key_id=key_id)
        prev = rec["hash"]
        hashes[expected_seq] = prev
        expected_seq += 1

    result = VerifyResult(ok=True, count=expected_seq, last_hash=prev if expected_seq else None,
                          key_id=key_id)
    # Truncation check against the signed head pointer.
    if head is None:
        if head_present:
            return VerifyResult(ok=False, count=expected_seq, broken_seq=expected_seq,
                                reason="head pointer is unreadable", key_id=key_id)
        if expected_seq:
            result.warnings.append("no head pointer: truncation of the newest records "
                                   "cannot be detected locally")
        return result
    head_body = {k: head.get(k) for k in ("seq", "hash", "key_id")}
    if head.get("key_id") != key_id or not verify_sig(pub, sha256_hex(canonical(head_body)),
                                                       str(head.get("sig", ""))):
        return VerifyResult(ok=False, count=expected_seq, broken_seq=expected_seq,
                            reason="head pointer signature is not valid", key_id=key_id)
    hseq = head.get("seq")
    if not isinstance(hseq, int) or hseq >= expected_seq:
        return VerifyResult(ok=False, count=expected_seq, broken_seq=expected_seq,
                            reason=(f"log was truncated: the signed head says seq {hseq} exists, "
                                    f"the log ends before seq {expected_seq}"),
                            key_id=key_id)
    if hashes.get(hseq) != head.get("hash"):
        return VerifyResult(ok=False, count=expected_seq, broken_seq=hseq,
                            reason="record does not match the signed head pointer", key_id=key_id)
    if hseq < expected_seq - 1:
        result.warnings.append(f"head pointer lags the log by {expected_seq - 1 - hseq} record(s) "
                               "(an interrupted write)")
    return result


# --------------------------------------------------------------------------- receipts

def stub_of(rec: dict) -> dict:
    return {"stub": True, "seq": rec["seq"], "prev_hash": rec["prev_hash"],
            "body_sha256": body_sha256(rec), "hash": rec["hash"], "sig": rec["sig"],
            "key_id": rec.get("key_id")}


def build_receipt(records: list[dict], session: str, keys: KeyPair,
                  head: Optional[dict] = None) -> dict:
    """A signed, self-contained proof of one session's records.

    Records of ``session`` are included in full; records of other sessions that
    fall between the session's first and last record are included as stubs, so
    the verifier can check the chain is unbroken without seeing them.
    """
    seqs = [r["seq"] for r in records if r.get("session") == session]
    if not seqs:
        raise ValueError(f"no records for session {session!r}")
    lo, hi = min(seqs), max(seqs)
    entries = []
    for rec in records:
        if lo <= rec["seq"] <= hi:
            entries.append(dict(rec) if rec.get("session") == session else stub_of(rec))
    entries.sort(key=lambda e: e["seq"])
    receipt = {
        "format": RECEIPT_FORMAT,
        "created": utc_now(),
        "session": session,
        "public_key": keys.public_b64,
        "key_id": keys.key_id,
        "range": [lo, hi],
        "entries": entries,
        "head": head,
        "summary": summarize(entries),
    }
    receipt["receipt_sig"] = keys.sign_hex(sha256_hex(canonical(receipt)))
    return receipt


def summarize(entries: list[dict]) -> dict:
    full = [e for e in entries if not e.get("stub")]
    by_kind: dict[str, int] = {}
    tools: dict[str, int] = {}
    for e in full:
        by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1
        if e["kind"] == "tool_call" and e.get("tool"):
            tools[e["tool"]] = tools.get(e["tool"], 0) + 1
    return {"records": len(full), "other_session_stubs": len(entries) - len(full),
            "by_kind": by_kind, "tools": tools}


def verify_receipt(receipt: dict, pubkey: Optional[str | Path] = None) -> VerifyResult:
    """Verify a receipt using only a public key (pinned, or the one embedded)."""
    warnings = []
    if receipt.get("format") != RECEIPT_FORMAT:
        return VerifyResult(ok=False, count=0, reason=f"unknown receipt format {receipt.get('format')!r}")
    try:
        pub = load_public_key(pubkey) if pubkey else load_public_key(str(receipt.get("public_key", "")))
    except Exception as exc:
        return VerifyResult(ok=False, count=0, reason=f"unusable public key: {exc}")
    if not pubkey:
        warnings.append("public key taken from the receipt itself: compare its key id with one "
                        "you obtained separately, or pass --pubkey")
    key_id = key_id_for(public_raw(pub))
    if receipt.get("key_id") != key_id:
        return VerifyResult(ok=False, count=0, reason=f"receipt names key {receipt.get('key_id')}, "
                            f"verifying with key {key_id}", key_id=key_id)
    unsigned = {k: v for k, v in receipt.items() if k != "receipt_sig"}
    if not verify_sig(pub, sha256_hex(canonical(unsigned)), str(receipt.get("receipt_sig", ""))):
        return VerifyResult(ok=False, count=0, reason="receipt signature is not valid", key_id=key_id)
    entries = receipt.get("entries") or []
    if not entries:
        return VerifyResult(ok=False, count=0, reason="receipt has no entries", key_id=key_id)
    prev = None
    expected = entries[0].get("seq")
    full = 0
    for e in entries:
        seq = e.get("seq")
        if seq != expected:
            return VerifyResult(ok=False, count=full, broken_seq=expected, key_id=key_id,
                                reason=f"entry seq {expected} is missing (found seq {seq})")
        if prev is not None and e.get("prev_hash") != prev:
            return VerifyResult(ok=False, count=full, broken_seq=seq, key_id=key_id,
                                reason="prev_hash does not match the previous entry: chain broken")
        if e.get("stub"):
            digest = link_hash(seq, e["prev_hash"], e["body_sha256"])
        else:
            missing = [f for f in _REQUIRED if f not in e]
            if missing:
                return VerifyResult(ok=False, count=full, broken_seq=seq, key_id=key_id,
                                    reason=f"entry is missing field(s): {', '.join(missing)}")
            if e.get("session") != receipt.get("session"):
                return VerifyResult(ok=False, count=full, broken_seq=seq, key_id=key_id,
                                    reason="full entry belongs to a different session")
            digest = record_hash(e)
            full += 1
        if digest != e.get("hash"):
            return VerifyResult(ok=False, count=full, broken_seq=seq, key_id=key_id,
                                reason="content does not match its hash: entry was edited")
        if e.get("key_id") != key_id or not verify_sig(pub, digest, str(e.get("sig", ""))):
            return VerifyResult(ok=False, count=full, broken_seq=seq, key_id=key_id,
                                reason="entry signature is not valid for this public key")
        prev = digest
        expected = seq + 1
    lo, hi = (receipt.get("range") or [None, None])
    if entries[0]["seq"] != lo or entries[-1]["seq"] != hi:
        return VerifyResult(ok=False, count=full, key_id=key_id,
                            reason="entries do not cover the receipt's stated range")
    return VerifyResult(ok=True, count=full, last_hash=prev, key_id=key_id, warnings=warnings)
