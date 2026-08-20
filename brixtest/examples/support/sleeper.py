"""Immediate-readiness process for the static-config example."""

import os
import sys
import time
from pathlib import Path

config = Path(sys.argv[1]).read_text().strip().replace("\n", ",")
print(f"mode={os.environ['EXAMPLE_MODE']} config={config}", flush=True)
time.sleep(300)
