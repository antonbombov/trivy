import os
from pathlib import Path

# Настройки путей
SCRIPT_DIR = Path(__file__).parent
SPLOITSCAN_DIR = SCRIPT_DIR.parent
SPLOITSCAN_PATH = SPLOITSCAN_DIR / "sploitscan.py"
TARGET_DIR = SCRIPT_DIR / "SploitScanJsons"

# Настройки обработки
TIMEOUT = 60
MAX_WORKERS_AUTO = True
DEFAULT_WORKERS = 3
MAX_RETRIES = 2

# Настройки кодировки
ENV = os.environ.copy()
ENV['PYTHONIOENCODING'] = 'utf-8'
ENV['PYTHONUTF8'] = '1'