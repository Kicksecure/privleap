#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite build script. Invoked inside the OSS-Fuzz
## base-builder-python container by the ClusterFuzzLite tooling.
##
## Standard OSS-Fuzz contract:
##   - $SRC      - source root (we COPY the repo here in the Dockerfile)
##   - $OUT      - output directory; harnesses go here
##   - compile_python_fuzzer - OSS-Fuzz helper that wraps a python
##                              harness into a runnable executable
##                              and copies it to $OUT/
##
## NOTE: no CI-guard here. This script is invoked by ClusterFuzzLite inside the
## OSS-Fuzz base-builder container; it does not see the GitHub Actions CI=true
## env var. The trust boundary is the container itself, not this script.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## SRC (and OUT / compile_python_fuzzer) are provided by the OSS-Fuzz
## base-builder container, not assigned in this script.
# shellcheck disable=SC2154

cd -- "${SRC}/privleap"

## Make the privleap package importable inside the harnesses. Both harnesses
## import only privleap.privleap, which is pure stdlib -- no extra pip deps.
export PYTHONPATH="${SRC}/privleap/usr/lib/python3/dist-packages${PYTHONPATH+:${PYTHONPATH}}"

## Wrap each fuzz/fuzz_*.py harness for OSS-Fuzz's Python runtime.
for harness in fuzz/fuzz_*.py; do
  name="$(basename -- "${harness}" .py)"
  ## compile_python_fuzzer overwrites PYTHONPATH (to fuzz-introspector), so
  ## PyInstaller cannot see the privleap package via the export above. Point it
  ## at the package dir with --paths, and --collect-submodules so the same-name
  ## privleap.privleap module is bundled and importable in the frozen harness.
  compile_python_fuzzer "${harness}" \
    --paths "${SRC}/privleap/usr/lib/python3/dist-packages" \
    --collect-submodules privleap
  printf 'compiled %s\n' "${name}"
done
