import hashlib
import json
import os
import re
import time
import urllib.request
from typing import Any, Dict, List, Optional


class SelfLearningPipeline:
    def __init__(self, knowledge_dir: str = "knowledge", skills_dir: str = "skills"):
        self.knowledge_dir = os.path.abspath(knowledge_dir)
        self.skills_dir = os.path.abspath(skills_dir)
        self.index_path = os.path.abspath("output/learning/index.json")
        os.makedirs(self.knowledge_dir, exist_ok=True)
        os.makedirs(self.skills_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.index_path), exist_ok=True)

    def _load_index(self) -> Dict[str, Any]:
        if not os.path.exists(self.index_path):
            return {"items": []}
        try:
            with open(self.index_path, "r", encoding="utf-8") as file:
                data = json.load(file)
            if isinstance(data, dict) and isinstance(data.get("items"), list):
                return data
        except Exception:
            pass
        return {"items": []}

    def _save_index(self, index_data: Dict[str, Any]) -> None:
        with open(self.index_path, "w", encoding="utf-8") as file:
            json.dump(index_data, file, ensure_ascii=False, indent=2)

    @staticmethod
    def _clean_text(raw: str) -> str:
        text = re.sub(r"<[^>]+>", " ", raw)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    @staticmethod
    def _to_slug(name: str) -> str:
        slug = re.sub(r"[^a-zA-Z0-9_\u4e00-\u9fa5-]+", "-", name).strip("-")
        return slug[:80] or f"learning-{int(time.time())}"

    def _is_skill_like(self, text: str) -> bool:
        hint_words = ["命令", "步骤", "工具", "参数", "利用", "扫描", "提权", "横向"]
        return any(word in text for word in hint_words)

    def _fetch_url(self, url: str, timeout: int = 15) -> str:
        request = urllib.request.Request(
            url=url,
            headers={
                "User-Agent": "Mozilla/5.0 WRAPT-Learning/1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
        return data.decode("utf-8", errors="ignore")

    def ingest_text(self, topic: str, text: str, source: str) -> Dict[str, Any]:
        cleaned = self._clean_text(text)
        digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()
        index_data = self._load_index()
        existing = next((item for item in index_data["items"] if item.get("hash") == digest), None)
        if existing:
            return {"saved": False, "duplicate": True, "file_path": existing.get("file_path"), "type": existing.get("type")}

        target_type = "skills" if self._is_skill_like(cleaned) else "knowledge"
        target_dir = self.skills_dir if target_type == "skills" else self.knowledge_dir
        filename = f"{self._to_slug(topic)}-{int(time.time())}.md"
        file_path = os.path.join(target_dir, filename)
        content = (
            f"# {topic}\n\n"
            f"- 来源: {source}\n"
            f"- 采集时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n\n"
            f"## 内容\n\n{cleaned}\n"
        )
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(content)

        index_data["items"].append(
            {
                "hash": digest,
                "topic": topic,
                "source": source,
                "type": target_type,
                "file_path": file_path,
                "created_at": time.time(),
            }
        )
        self._save_index(index_data)
        return {"saved": True, "duplicate": False, "file_path": file_path, "type": target_type}

    def ingest_urls(self, topic: str, urls: List[str]) -> Dict[str, Any]:
        results: List[Dict[str, Any]] = []
        for url in urls:
            try:
                raw = self._fetch_url(url)
                result = self.ingest_text(topic=topic, text=raw[:20000], source=url)
                results.append({"url": url, **result})
            except Exception as error:
                results.append({"url": url, "saved": False, "error": str(error)})
        return {
            "topic": topic,
            "total": len(results),
            "saved_count": sum(1 for item in results if item.get("saved")),
            "duplicate_count": sum(1 for item in results if item.get("duplicate")),
            "results": results,
        }

    def ingest_markdown_experience(self, topic: str, content: str, target_type: str = "skills", source: str = "Self-Reflection") -> Dict[str, Any]:
        """Ingests AI-generated markdown experience with content deduplication and without destroying formatting."""
        # Calculate hash for content deduplication using raw content
        digest = hashlib.sha256(content.strip().encode("utf-8")).hexdigest()
        index_data = self._load_index()
        
        # Deduplication check
        existing = next((item for item in index_data["items"] if item.get("hash") == digest), None)
        if existing:
            return {"saved": False, "duplicate": True, "file_path": existing.get("file_path"), "type": existing.get("type")}
            
        target_dir = self.skills_dir if target_type == "skills" else self.knowledge_dir
        
        # Filename generation and deduplication
        base_slug = self._to_slug(topic)
        filename = f"{base_slug}.md"
        file_path = os.path.join(target_dir, filename)
        
        # If filename exists (but content differs, otherwise caught by hash check), append counter
        counter = 1
        while os.path.exists(file_path):
            filename = f"{base_slug}_{counter}.md"
            file_path = os.path.join(target_dir, filename)
            counter += 1
            
        # Prepare banner
        if target_type == "knowledge":
            banner = "> [!NOTE] 雾刃自动化渗透测试平台知识库 (WuRen Knowledge Base)\n> 提供渗透测试方法论、ATT&CK框架与安全理论指导。\n\n"
        else:
            banner = "> [!NOTE] 雾刃自动化渗透测试平台技能库 (WuRen Skill Base)\n> 类别: AI自主总结实战经验\n> 用途: 记录并复用渗透测试中成功的攻击Payload、绕过技巧与工作流。\n\n"
            
        final_content = (
            f"---\n"
            f"title: {topic}\n"
            f"source: {source}\n"
            f"created_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"---\n\n"
            f"{banner}"
            f"# {topic}\n\n"
            f"{content}\n"
        )
        
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(final_content)
            
        index_data["items"].append(
            {
                "hash": digest,
                "topic": topic,
                "source": source,
                "type": target_type,
                "file_path": file_path,
                "created_at": time.time(),
            }
        )
        self._save_index(index_data)
        return {"saved": True, "duplicate": False, "file_path": file_path, "type": target_type}

    def list_history(
        self,
        keyword: Optional[str] = None,
        item_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        index_data = self._load_index()
        items = list(index_data.get("items", []))
        items.sort(key=lambda row: float(row.get("created_at", 0)), reverse=True)
        if keyword:
            kw = keyword.strip().lower()
            items = [
                row
                for row in items
                if kw in str(row.get("topic", "")).lower()
                or kw in str(row.get("source", "")).lower()
                or kw in str(row.get("file_path", "")).lower()
            ]
        if item_type and item_type in {"knowledge", "skills"}:
            items = [row for row in items if row.get("type") == item_type]
        total = len(items)
        if offset < 0:
            offset = 0
        if limit <= 0:
            limit = 50
        page = items[offset : offset + limit]
        return {"total": total, "items": page, "limit": limit, "offset": offset}
