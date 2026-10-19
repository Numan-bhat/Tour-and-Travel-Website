"""Production WSGI entry point."""

from pathlib import Path
import sys

# Hosting providers do not always start the process in the project directory.
# Make the local application module importable in that case.
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import app

application = app
