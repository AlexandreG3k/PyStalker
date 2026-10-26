"""
Utility functions for PyStalker.
"""
import os
import shutil
import subprocess
import random
import platform
from urllib.parse import urlparse
from core.config import USER_AGENTS

_TOOL_CACHE = {}

def get_random_agent() -> str:
    """Returns a random modern User-Agent."""
    return random.choice(USER_AGENTS)

def clean_domain(raw_target: str) -> str:
    """Extracts a clean hostname from URL or string."""
    raw = raw_target.strip().lower()
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = parsed.netloc or parsed.path
    if ":" in host:
        host = host.split(":")[0]
    return host.strip("/").strip()

def resolve_tool_path(tool_name: str) -> str | None:
    """
    Locates an executable binary quickly and reliably.
    Caches results in memory for maximum speed.
    """
    if tool_name in _TOOL_CACHE:
        return _TOOL_CACHE[tool_name]

    # 1. System PATH
    path = shutil.which(tool_name)
    if path:
        _TOOL_CACHE[tool_name] = path
        return path

    # 2. Known directories
    home = os.path.expanduser("~")
    candidate_paths = [
        f"/usr/local/bin/{tool_name}",
        f"/usr/bin/{tool_name}",
        f"/bin/{tool_name}",
        os.path.join(home, "go", "bin", tool_name),
        os.path.join(home, ".local", "bin", tool_name),
        os.path.join(home, "bin", tool_name),
        f"/opt/{tool_name}/{tool_name}",
        f"/opt/{tool_name}"
    ]

    for p in candidate_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            _TOOL_CACHE[tool_name] = p
            return p

    # 3. Locate database fallback if available
    try:
        cmd = ["locate", "-b", f"\\{tool_name}"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        for line in res.stdout.strip().splitlines():
            line = line.strip()
            if os.path.basename(line) == tool_name and os.access(line, os.X_OK):
                _TOOL_CACHE[tool_name] = line
                return line
    except Exception:
        pass

    _TOOL_CACHE[tool_name] = None
    return None

def open_report(report_path: str) -> bool:
    """Opens the generated HTML report in the default web browser."""
    try:
        abs_path = os.path.abspath(report_path)
        system = platform.system()
        if system == "Windows":
            os.startfile(abs_path)
        elif system == "Darwin":
            subprocess.run(["open", abs_path], check=True)
        else:
            subprocess.run(["xdg-open", abs_path], check=True)
        return True
    except Exception:
        return False

def copy_to_clipboard(text: str) -> bool:
    """Copies text to the system clipboard."""
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(["clip"], input=text.encode(), check=True)
            return True
        elif system == "Darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True)
            return True
        else:
            if shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
                return True
            elif shutil.which("xsel"):
                subprocess.run(["xsel", "--clipboard", "--input"], input=text.encode(), check=True)
                return True
    except Exception:
        pass
    return False
