import os
from pathlib import Path

HOME = Path(os.environ.get("HMTP_HOME", Path.home() / ".hmtp"))
INSECURE = os.environ.get("HMTP_INSECURE") == "1"  # plain HTTP, local tests only
HOST = os.environ.get("HMTP_HOST", "127.0.0.1")  # 0.0.0.0 inside containers
