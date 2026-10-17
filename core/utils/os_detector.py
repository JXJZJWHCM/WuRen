import os

def detect_os() -> str:
    """
    通过读取 /etc/os-release 文件来探测当前操作系统的发行版 ID。
    例如：返回 "kali", "ubuntu", "debian" 等。
    如果在 Windows 或无法读取该文件，则返回 "unknown"。
    """
    os_release_path = "/etc/os-release"
    if not os.path.exists(os_release_path):
        return "unknown"
    
    try:
        with open(os_release_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("ID="):
                    # 获取 ID= 后面的部分，并去除可能的引号
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        return parts[1].strip('"').strip("'").lower()
    except Exception:
        pass
    
    return "unknown"
