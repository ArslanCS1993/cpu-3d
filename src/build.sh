#!/bin/bash
# Rebuild the generated pages. Needs vmlinux + the two traces in this directory.
#   cp /path/to/vmlinux trace.json trace-sched.json .
set -euo pipefail
cd "$(dirname "$0")"
python3 test-x86sem.py
python3 build-viewer.py trace.json      -o ../syscall-viewer.html
python3 build-viewer.py trace-sched.json -o ../sched-viewer.html
python3 gen-scene-preview.py --trace trace.json --step 4 -o ../scene-push.html
echo "rebuilt pages in $(cd .. && pwd)"
