import os
import shutil
from pathlib import Path
from typing import Dict, List, Tuple

from loguru import logger

ROOT = Path(__file__).resolve().parent.parent

SYNC_MAP: Dict[str, List[str]] = {
    "fingerprints": ["fingerprints", "fmaps"],
    "plugins": ["plugins", "cj"],
    "repo": ["repo"],
    "vuldb": ["vuldb"],
    "knowledge": ["knowledge"],
    "skills": ["skills"],
    "vuldb/poc_exp": ["vuldb/poc_exp"],
    "tools": ["tools", "tools/custom_tools"],
}


def _copy_item(src: Path, dst: Path) -> bool:
    if dst.exists():
        return False
    if src.is_dir():
        shutil.copytree(src, dst)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return True


def sync_layout() -> List[Tuple[str, int, int]]:
    summary: List[Tuple[str, int, int]] = []
    for target, source_candidates in SYNC_MAP.items():
        target_dir = ROOT / target
        target_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        skipped = 0
        for source_rel in source_candidates:
            source_dir = ROOT / source_rel
            if not source_dir.exists():
                continue
            for item in source_dir.iterdir():
                destination = target_dir / item.name
                try:
                    if _copy_item(item, destination):
                        copied += 1
                    else:
                        skipped += 1
                except Exception as error:
                    logger.warning(f"同步失败: {item} -> {destination}, error={error}")
        summary.append((target, copied, skipped))
    return summary


def main() -> None:
    logger.info("开始同步资源目录到新统一布局")
    summary = sync_layout()
    for target, copied, skipped in summary:
        logger.info(f"{target}: copied={copied}, skipped={skipped}")
    logger.info("资源目录同步完成")


if __name__ == "__main__":
    main()
