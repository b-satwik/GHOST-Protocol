"""
Central Environment Configuration Module for DARKWATCH.
Loads environment variables from project-root .env file and provides API status reporting.
"""

import os
from pathlib import Path

# Locate project root directory (darkwatch)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

def _parse_env_file(path: Path) -> None:
    """Fallback manual parser for .env files if python-dotenv is absent."""
    if not path.exists():
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
    except Exception:
        pass

def load_project_env() -> bool:
    """
    Loads project-root .env environment configuration if present.
    Returns True if GEMINI_API_KEY (or GOOGLE_API_KEY) is configured with a non-empty value.
    """
    try:
        from dotenv import load_dotenv
        if ENV_FILE.exists():
            load_dotenv(dotenv_path=ENV_FILE, override=False)
        else:
            load_dotenv(override=False)
    except ImportError:
        _parse_env_file(ENV_FILE)

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    return bool(api_key and api_key.strip())

def check_gemini_config() -> str:
    """
    Startup/configuration check that reports ONLY:
    'GEMINI API: CONFIGURED' or 'GEMINI API: NOT CONFIGURED'
    Never prints or exposes the secret itself.
    """
    is_configured = load_project_env()
    return "GEMINI API: CONFIGURED" if is_configured else "GEMINI API: NOT CONFIGURED"

def print_gemini_config_status() -> None:
    """
    Prints the startup configuration check result.
    """
    print(check_gemini_config())
