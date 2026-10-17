from pathlib import Path
import json
import re
import shutil

import yaml
from loguru import logger


class LibManager:
    """Manage and normalize platform libraries."""

    def _sanitize_filename(self, name: str) -> str:
        safe_name = re.sub(r'[\\/*?:"<>|]', '_', str(name or ""))
        safe_name = safe_name.strip()
        return safe_name or "unnamed"

    def _get_unique_path(self, directory: Path, filename: str, extension: str) -> Path:
        sanitized_name = self._sanitize_filename(filename)
        base_path = directory / f"{sanitized_name}{extension}"
        if not base_path.exists():
            return base_path

        counter = 1
        while True:
            new_path = directory / f"{sanitized_name}_{counter}{extension}"
            if not new_path.exists():
                return new_path
            counter += 1

    def standardize_fingerprints(self, directory: str):
        """Rename fingerprint JSON files to their logical fingerprint names."""
        target_dir = Path(directory)
        if not target_dir.exists():
            logger.warning(f"Directory not found: {directory}")
            return

        logger.info(f"Starting fingerprint standardization in {directory}")
        count = 0

        for file_path in list(target_dir.glob("*")):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(content)
                name = data.get("指纹名称") or data.get("name") or data.get("fingerprint")
                if not name:
                    logger.warning(f"No fingerprint name found in {file_path.name}")
                    continue
                new_path = self._get_unique_path(target_dir, str(name), ".json")
                if new_path.resolve() != file_path.resolve():
                    file_path.rename(new_path)
                    logger.debug(f"Renamed {file_path.name} -> {new_path.name}")
                    count += 1
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON: {file_path.name}")
            except Exception as error:
                logger.error(f"Error processing {file_path.name}: {error}")

        logger.info(f"Finished standardizing fingerprints. Renamed {count} files.")

    def standardize_plugins(self, directory: str):
        """Rename plugin JSON files to their script names."""
        target_dir = Path(directory)
        if not target_dir.exists():
            logger.warning(f"Directory not found: {directory}")
            return

        logger.info(f"Starting plugin standardization in {directory}")
        count = 0

        for file_path in list(target_dir.glob("*")):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(content)
                name = data.get("script_name")
                if not name:
                    logger.warning(f"No script_name found in {file_path.name}")
                    continue
                new_path = self._get_unique_path(target_dir, str(name), ".json")
                if new_path.resolve() != file_path.resolve():
                    file_path.rename(new_path)
                    logger.debug(f"Renamed {file_path.name} -> {new_path.name}")
                    count += 1
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON: {file_path.name}")
            except Exception as error:
                logger.error(f"Error processing {file_path.name}: {error}")

        logger.info(f"Finished standardizing plugins. Renamed {count} files.")

    def standardize_rules(self, directory: str):
        """Rename rule files based on id/name/info.name."""
        target_dir = Path(directory)
        if not target_dir.exists():
            logger.warning(f"Directory not found: {directory}")
            return

        logger.info(f"Starting rules standardization in {directory}")
        count = 0

        for file_path in list(target_dir.glob("*")):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                data = None
                if file_path.suffix.lower() == ".json":
                    try:
                        data = json.loads(content)
                    except Exception:
                        data = None
                if data is None:
                    try:
                        data = yaml.safe_load(content)
                    except Exception:
                        data = None
                if not isinstance(data, dict):
                    logger.warning(f"Could not parse {file_path.name} as JSON or YAML")
                    continue

                name = data.get("id") or data.get("name")
                if not name:
                    info = data.get("info", {})
                    if isinstance(info, dict):
                        name = info.get("name") or info.get("id")
                if not name:
                    logger.warning(f"No id/name found in {file_path.name}")
                    continue

                ext = file_path.suffix.lower() or ".yaml"
                if ext == ".txt":
                    ext = ".yaml"
                new_path = self._get_unique_path(target_dir, str(name), ext)
                if new_path.resolve() != file_path.resolve():
                    file_path.rename(new_path)
                    logger.debug(f"Renamed {file_path.name} -> {new_path.name}")
                    count += 1
            except Exception as error:
                logger.error(f"Error processing {file_path.name}: {error}")

        logger.info(f"Finished standardizing rules. Renamed {count} files.")

    def convert_vuldb(self, directory: str):
        """
        Convert/organize vulnerability templates into platform poc_exp layout.

        Rules:
        - only keep Nuclei-style YAML templates;
        - only keep templates with clear POC/EXP signals;
        - preserve relative hierarchy under vuldb/poc_exp.
        """
        source_dir = Path(directory)
        if not source_dir.exists():
            logger.warning(f"Directory not found: {directory}")
            return

        dest_dir = source_dir / "poc_exp"
        dest_dir.mkdir(parents=True, exist_ok=True)

        keyword_set = {
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
        }

        def _extract_info(doc: dict) -> str:
            info = doc.get("info", {}) if isinstance(doc, dict) else {}
            if not isinstance(info, dict):
                info = {}
            fields = [
                str(doc.get("id", "")),
                str(info.get("name", "")),
                str(info.get("tags", "")),
                str(info.get("description", "")),
            ]
            return " ".join(fields).lower()

        logger.info(f"Starting vuldb conversion in {directory} -> {dest_dir} (POC/EXP only)")
        count = 0

        for file_path in source_dir.rglob("*"):
            if not file_path.is_file() or file_path.suffix.lower() not in {".yaml", ".yml"}:
                continue
            try:
                file_path.resolve().relative_to(dest_dir.resolve())
                continue
            except ValueError:
                pass

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                try:
                    data = yaml.safe_load(content)
                except Exception:
                    data = None

                searchable_text = _extract_info(data) if isinstance(data, dict) else content.lower()
                if not any(token in searchable_text for token in keyword_set):
                    continue

                relative_path = file_path.relative_to(source_dir)
                destination = dest_dir / relative_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file_path, destination)
                count += 1
            except Exception as error:
                logger.error(f"Error processing {file_path.name}: {error}")

        logger.info(f"Finished converting vuldb. Retained {count} POC/EXP templates.")
