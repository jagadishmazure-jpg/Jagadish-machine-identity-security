"""Print the real test total (used by CI docs check)."""

import subprocess
import sys

out = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
    capture_output=True, text=True, cwd=".")
total = 0
for line in out.stdout.splitlines():
    line = line.strip()
    if "::" in line and not line.startswith("tests/"):
        total += 1
    elif line.startswith("tests/test_") and "::" in line:
        total += 1
print(f"total tests: {total}")
