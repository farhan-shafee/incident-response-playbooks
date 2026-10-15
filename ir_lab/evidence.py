"""Offline case loading, raw-byte evidence verification, and no-overwrite output."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

from .contracts import CaseError, document, require

MAX_CASE_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 524_288
SAFE_RELATIVE = re.compile(r"^[a-zA-Z0-9._/-]+$")


def json_pairs(items: list[tuple[str, object]]) -> dict:
    value: dict = {}
    for key, element in items:
        require(key not in value, "JSON: duplicate object key")
        value[key] = element
    return value


def case_from_file(path: str | Path) -> dict:
    file = Path(path)
    require(file.is_file() and not file.is_symlink(), "case: missing or symlink file")
    try:
        with file.open("rb") as handle:
            raw = handle.read(MAX_CASE_BYTES + 1)
        require(len(raw) <= MAX_CASE_BYTES, "case: file too large")
        case = json.loads(raw.decode("utf-8"), object_pairs_hook=json_pairs,
                          parse_constant=lambda v: (_ for _ in ()).throw(CaseError("JSON: nonfinite number")))
    except CaseError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, ValueError) as exc:
        raise CaseError("case: invalid UTF-8 JSON, oversized number, or excessive nesting") from exc
    except OSError as exc:
        raise CaseError("case: cannot read file") from exc
    return document(case)


def safe_artifact(case_dir: Path, value: str) -> Path:
    require(bool(SAFE_RELATIVE.fullmatch(value)) and
            not value.startswith("/") and ":" not in value and "\\" not in value,
            "evidence: unsafe path")
    components = PurePosixPath(value).parts
    require(bool(components) and all(part not in (".", "..") for part in components),
            "evidence: unsafe relative components")
    candidate = case_dir.joinpath(*components)
    for item in [case_dir, *[case_dir.joinpath(*components[:i]) for i in range(1, len(components) + 1)]]:
        require(not item.is_symlink(), "evidence: symlink path prohibited")
    require(candidate.is_file(), "evidence: artifact missing or not a file")
    require(candidate.resolve().is_relative_to(case_dir.resolve()), "evidence: path escapes case directory")
    return candidate


def normalized_utf8_v1(raw: bytes) -> bytes:
    text = raw.decode("utf-8-sig")
    return text.replace("\r\n", "\n").encode("utf-8")


def validate_artifacts(case: dict, case_path: str | Path) -> list[dict]:
    folder = Path(case_path).parent
    verified: list[dict] = []
    seen_paths: list[Path] = []
    retained_bytes: dict[str, bytes] = {}
    for item in case["evidence"]:
        location = safe_artifact(folder, item["path"])
        try:
            require(not any(location.samefile(earlier) for earlier in seen_paths),
                    "evidence: duplicate physical artifact, alias, or hard link")
            with location.open("rb") as stream:
                raw = stream.read(MAX_EVIDENCE_BYTES + 1)
        except OSError as exc:
            raise CaseError("evidence: cannot read or identify artifact") from exc
        seen_paths.append(location)
        require(len(raw) <= MAX_EVIDENCE_BYTES, "evidence: artifact too large")
        require(len(raw) == item["byte_length"], f"evidence {item['id']}: byte length mismatch")
        require(hashlib.sha256(raw).hexdigest() == item["sha256"],
                f"evidence {item['id']}: raw SHA-256 mismatch")
        retained_bytes[item["id"]] = raw
        if "normalization" in item:
            try:
                normalized = normalized_utf8_v1(raw)
            except UnicodeError as exc:
                raise CaseError(f"evidence {item['id']}: invalid normalized UTF-8") from exc
            require(hashlib.sha256(normalized).hexdigest() == item["normalized_sha256"],
                    f"evidence {item['id']}: normalized SHA-256 mismatch")
        verified.append({"id": item["id"], "sha256_raw": item["sha256"],
                         "byte_length": item["byte_length"], "kind": item["kind"],
                         "source": item["source"], "collected_at": item["collected_at"],
                         "path": item["path"],
                         **({"parent_id": item["parent_id"], "transformation": item["transformation"]}
                            if item["kind"] == "derived" else {}),
                         **({"normalization": item["normalization"],
                             "sha256_normalized": item["normalized_sha256"]}
                            if "normalization" in item else {})})
    for item in case["evidence"]:
        if item["kind"] == "derived":
            try:
                expected = normalized_utf8_v1(retained_bytes[item["parent_id"]])
            except UnicodeError as exc:
                raise CaseError(f"evidence {item['id']}: invalid UTF-8 parent for derivation") from exc
            require(retained_bytes[item["id"]] == expected,
                    f"evidence {item['id']}: derived bytes disagree with transformation")
    return sorted(verified, key=lambda item: item["id"])


def canonical_json(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def write_new_file(target: str | Path, raw: bytes, case_path: str | Path, case: dict) -> None:
    """Atomically create only a NEW output; never overwrite evidence/case/existing file.

    A hard link from a fully written temporary sibling makes the no-clobber
    final-name creation atomic. This requires a filesystem supporting hard links.
    """
    path = Path(target).absolute()
    source = Path(case_path).absolute()
    require(path != source and not path.exists() and not path.is_symlink(),
            "output: source alias or destination already exists")
    require(path.parent.is_dir(), "output: parent directory must already exist")
    for ancestor in [path.parent, *path.parent.parents]:
        require(not ancestor.is_symlink(), "output: symlink parent prohibited")
    forbidden = {source.resolve()} | {
        safe_artifact(source.parent, item["path"]).resolve() for item in case["evidence"]
    }
    require(path.resolve() not in forbidden, "output: cannot alias case or source artifact")
    fd: int | None = None
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".ir-output-", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except OSError as exc:
        raise CaseError(f"output: cannot atomically create destination ({exc.strerror or 'I/O error'})") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
