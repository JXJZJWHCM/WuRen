import argparse
import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import yaml
except Exception:  # pragma: no cover - optional dependency fallback
    yaml = None

import re


POC_EXP_KEYWORDS = [
    "poc",
    "exp",
    "exploit",
    "vuln",
    "vulnerability",
    "cve-",
    "rce",
    "sqli",
    "sql injection",
    "xss",
    "xxe",
    "ssrf",
    "lfi",
    "rfi",
    "command injection",
    "cmd injection",
    "deserialization",
    "file upload",
    "auth bypass",
    "unauthorized",
    "directory traversal",
    "path traversal",
    "漏洞",
    "注入",
    "远程代码执行",
    "命令执行",
    "提权",
]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return str(value)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_fields_from_text(text: str) -> Dict[str, Any]:
    id_match = re.search(r"(?mi)^\s*id\s*:\s*(.+?)\s*$", text)
    info_match = re.search(r"(?ms)^\s*info\s*:\s*(.*?)(?:^\S|\Z)", text)
    info_block = info_match.group(1) if info_match else ""

    name_match = re.search(r"(?mi)^\s*name\s*:\s*(.+?)\s*$", info_block)
    desc_match = re.search(r"(?mi)^\s*description\s*:\s*(.+?)\s*$", info_block)
    tags_inline_match = re.search(r"(?mi)^\s*tags\s*:\s*(.+?)\s*$", info_block)
    tags_value = tags_inline_match.group(1).strip() if tags_inline_match else ""
    if tags_inline_match and not tags_value:
        # Handle YAML block format:
        # tags:
        #   - x
        #   - y
        start = tags_inline_match.end()
        tail = info_block[start:]
        tag_lines = re.findall(r"(?mi)^\s*-\s*(.+?)\s*$", tail)
        tags_value = ",".join(tag_lines)

    return {
        "id": id_match.group(1).strip() if id_match else "",
        "info": {
            "name": name_match.group(1).strip() if name_match else "",
            "description": desc_match.group(1).strip() if desc_match else "",
            "tags": tags_value,
        },
    }


def _load_template(path: Path) -> Tuple[Dict[str, Any], str]:
    raw_text = path.read_text(encoding="utf-8", errors="ignore")
    if yaml is None:
        return _extract_fields_from_text(raw_text), ""
    try:
        data = yaml.safe_load(raw_text)
        if isinstance(data, dict):
            return data, ""
        return _extract_fields_from_text(raw_text), "yaml root is not object"
    except Exception as error:
        return _extract_fields_from_text(raw_text), str(error)


def _match_keywords(data: Dict[str, Any]) -> Dict[str, List[str]]:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    fields = {
        "id": _text(data.get("id")),
        "info.name": _text(info.get("name")),
        "info.tags": _text(info.get("tags")),
        "info.description": _text(info.get("description")),
    }
    matched: Dict[str, List[str]] = {}
    for field, raw in fields.items():
        lowered = raw.lower()
        hit = [keyword for keyword in POC_EXP_KEYWORDS if keyword in lowered]
        if hit:
            matched[field] = sorted(set(hit))
    return matched


def _resolve_sources() -> List[Path]:
    candidates = [Path("vuldb/nuclei-templates"), Path("vuldb/nuclei")]
    return [item.resolve() for item in candidates if item.exists() and item.is_dir()]


def migrate(dry_run: bool = False, keep_source: bool = False) -> Dict[str, Any]:
    sources = _resolve_sources()
    target_root = Path("vuldb/poc_exp").resolve()
    if not dry_run:
        target_root.mkdir(parents=True, exist_ok=True)

    stats = {
        "files_scanned": 0,
        "files_migrated": 0,
        "files_skipped": 0,
        "files_parse_error": 0,
        "conflicts": 0,
    }
    entries: List[Dict[str, Any]] = []
    parse_errors: List[Dict[str, str]] = []

    for source_root in sources:
        for file_path in source_root.rglob("*"):
            if not file_path.is_file() or file_path.suffix.lower() not in {".yaml", ".yml"}:
                continue

            stats["files_scanned"] += 1
            relative = file_path.relative_to(source_root)
            data, parse_error = _load_template(file_path)
            if parse_error:
                stats["files_parse_error"] += 1
                parse_errors.append(
                    {
                        "source": str(file_path).replace("\\", "/"),
                        "error": parse_error,
                    }
                )
                continue

            matched_fields = _match_keywords(data)
            if not matched_fields:
                stats["files_skipped"] += 1
                continue

            destination = (target_root / relative).resolve()
            if destination.exists() and destination.is_file():
                if _sha256(destination) != _sha256(file_path):
                    stats["conflicts"] += 1
                    destination = (target_root / source_root.name / relative).resolve()

            if not dry_run:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, destination)

            stats["files_migrated"] += 1
            entries.append(
                {
                    "source": str(file_path).replace("\\", "/"),
                    "destination": str(destination).replace("\\", "/"),
                    "relative_path": str(relative).replace("\\", "/"),
                    "matched_fields": matched_fields,
                }
            )

    manifest = {
        "generated_at": int(time.time()),
        "dry_run": dry_run,
        "keep_source": keep_source,
        "keywords": POC_EXP_KEYWORDS,
        "source_roots": [str(item).replace("\\", "/") for item in sources],
        "target_root": str(target_root).replace("\\", "/"),
        "stats": stats,
        "parse_errors": parse_errors,
        "entries": entries,
    }

    if not dry_run:
        manifest_path = target_root / "_manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        if not keep_source:
            for source in sources:
                if source.exists() and source != target_root:
                    shutil.rmtree(source, ignore_errors=True)

    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate nuclei templates to vuldb/poc_exp by POC/EXP keyword matching.")
    parser.add_argument("--dry-run", action="store_true", help="Scan and classify only, without copying/deleting files.")
    parser.add_argument("--keep-source", action="store_true", help="Keep original nuclei directories after migration.")
    args = parser.parse_args()
    result = migrate(dry_run=args.dry_run, keep_source=args.keep_source)
    print(json.dumps({"stats": result.get("stats"), "target_root": result.get("target_root")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
