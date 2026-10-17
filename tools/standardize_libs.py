import sys
from pathlib import Path

from loguru import logger

# 添加项目根目录到 sys.path，确保可以导入 core 模块。
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

from core.library_manager import LibManager

def main():
    logger.info("Starting library standardization script...")
    
    manager = LibManager()

    # 1. 标准化指纹 (fingerprints)
    fmaps_path = "fingerprints"
    logger.info(f"Standardizing fingerprints in '{fmaps_path}'...")
    manager.standardize_fingerprints(fmaps_path)

    # 2. 标准化插件 (plugins)
    cj_path = "plugins"
    logger.info(f"Standardizing plugins in '{cj_path}'...")
    manager.standardize_plugins(cj_path)

    # 3. 标准化规则 (repo) - 如果存在
    repo_path = "repo"
    if Path(repo_path).exists():
        logger.info(f"Standardizing rules in '{repo_path}'...")
        manager.standardize_rules(repo_path)
    else:
        logger.warning(f"Directory '{repo_path}' not found, skipping rules standardization.")

    # 4. 转换漏洞库 (vuldb) - 如果存在
    vuldb_path = "vuldb"
    if Path(vuldb_path).exists():
        logger.info(f"Converting vuldb in '{vuldb_path}'...")
        manager.convert_vuldb(vuldb_path)
    else:
        logger.warning(f"Directory '{vuldb_path}' not found, skipping vuldb conversion.")

    logger.info("Library standardization completed.")

if __name__ == "__main__":
    main()

