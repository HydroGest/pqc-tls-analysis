#!/bin/bash
# Sequential SPHINCS+ benchmark runner: clean + build + run per variant.
set -u
REF="$(dirname "$0")/sphincs-ref/ref"
OUT="$(dirname "$0")/logs"
mkdir -p "$OUT"

VARIANTS="sphincs-sha2-128f sphincs-shake-128f sphincs-sha2-192s sphincs-shake-192s sphincs-sha2-192f sphincs-shake-192f sphincs-sha2-256f sphincs-shake-256f"

for V in $VARIANTS; do
  echo "=== START $V $(date +%T) ==="
  cd "$REF" || exit 1
  make clean -s
  # build+run benchmark; capture both build and benchmark output
  make -j16 PARAMS="$V" benchmark > "$OUT/${V}.log" 2>&1
  rc=$?
  echo "=== END $V rc=$rc $(date +%T) ==="
  if [ $rc -ne 0 ]; then
    tail -30 "$OUT/${V}.log"
  fi
done
echo "ALL DONE"
