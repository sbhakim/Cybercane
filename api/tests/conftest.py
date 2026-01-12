import sys
from pathlib import Path


# Ensure the `api/` directory is on sys.path so tests can import `app.*`
CURRENT_FILE = Path(__file__).resolve()
API_DIR = CURRENT_FILE.parents[1]  # .../api
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))


