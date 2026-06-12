#!/usr/bin/env bash
# workload.sh — syscall-heavy benchmark workload
# Runs 100k iterations of fork+exec+wait — the same pattern used
# in the strace vs Tracery overhead benchmark.
#
# Usage:
#   bash workload.sh
#   bash workload.sh &   # background, capture PID with $!

set -euo pipefail

ITERATIONS=100000

for i in $(seq 1 $ITERATIONS); do
  cat /dev/null > /dev/null
done