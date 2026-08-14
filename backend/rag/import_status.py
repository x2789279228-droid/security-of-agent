"""
导入状态跟踪器

管理 MITRE ATT&CK / CAPEC 等外部知识库的导入进度。
支持状态查询，供前端轮询显示进度。
"""
import time
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# 全局导入锁：调度器与手动导入共用，防止并发导入互相覆盖单槽 ImportStatus
import_lock = asyncio.Lock()


class ImportStatus:
    def __init__(self):
        self.running = False
        self.source = ""
        self.progress = 0.0
        self.message = ""
        self.total_found = 0
        self.imported = 0
        self.skipped = 0
        self.errors = 0
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.error_details: list[str] = []

    def start(self, source: str):
        self.running = True
        self.source = source
        self.progress = 0.0
        self.message = "Starting..."
        self.total_found = 0
        self.imported = 0
        self.skipped = 0
        self.errors = 0
        self.started_at = time.time()
        self.finished_at = None
        self.error_details = []

    def update(self, progress: float, message: str):
        self.progress = progress
        self.message = message

    def finish(self, imported: int, skipped: int, errors: int, error_details: list[str] = None):
        self.running = False
        self.progress = 1.0
        self.imported = imported
        self.skipped = skipped
        self.errors = errors
        self.error_details = error_details or []
        self.finished_at = time.time()
        self.message = f"Complete: {imported} imported, {skipped} skipped, {errors} errors"

    def fail(self, error: str):
        self.running = False
        self.progress = 0.0
        self.message = f"Failed: {error}"
        self.errors += 1
        self.error_details.append(error)
        self.finished_at = time.time()

    def to_dict(self):
        return {
            "running": self.running,
            "source": self.source,
            "progress": self.progress,
            "message": self.message,
            "total_found": self.total_found,
            "imported": self.imported,
            "skipped": self.skipped,
            "errors": self.errors,
            "elapsed": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "error_details": self.error_details[:5],
        }


# 全局导入状态
_current_import: Optional[ImportStatus] = None


def get_import_status() -> Optional[ImportStatus]:
    return _current_import


def set_import_status(status: Optional[ImportStatus]):
    global _current_import
    _current_import = status
