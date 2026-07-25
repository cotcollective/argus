"""Argus configuration."""

import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Config:
    ollama_host: str = os.environ.get("ARGUS_OLLAMA_HOST", "http://127.0.0.1:11434")
    ollama_model: str = os.environ.get("ARGUS_OLLAMA_MODEL", "qwen2.5:7b")
    proxy: str = os.environ.get("ARGUS_PROXY", "")
    concurrency: int = int(os.environ.get("ARGUS_CONCURRENCY", "20"))
    timeout: int = int(os.environ.get("ARGUS_TIMEOUT", "30"))
    cariddi_path: str = os.environ.get("ARGUS_CARIDDI", "cariddi")
    geolite2_db: str = os.environ.get(
        "ARGUS_GEOLITE2_DB",
        str(Path.home() / ".argus" / "GeoLite2-City.mmdb"),
    )
    breach_db: str = os.environ.get(
        "ARGUS_BREACH_DB",
        str(Path.home() / ".argus" / "breaches.db"),
    )
    report_dir: str = os.environ.get(
        "ARGUS_REPORT_DIR",
        str(Path.cwd() / "reports"),
    )
    github_token: str = os.environ.get("ARGUS_GITHUB_TOKEN", "")  # optional, raises rate limit
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

    def to_dict(self):
        return {
            k: str(v) if not isinstance(v, (int, str)) else v
            for k, v in self.__dict__.items()
        }


config = Config()