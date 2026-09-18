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

## The base python (3.11) cannot parse privleap's 3.12+ f-strings. Use the
## pinned portable CPython 3.12 the Dockerfile installed, FIRST on PATH, so
## pyinstaller and its import analysis both run under 3.12 and the onefile
## bundles a 3.12 interpreter. atheris + pyinstaller are the base's tools for
## its own python; reinstall them for 3.12.
export PATH="/opt/py312/bin:${PATH}"
python3 -m pip install --quiet --upgrade pip
python3 -m pip install --quiet pyinstaller atheris

## Make the privleap package importable inside the harnesses. Both harnesses
## import only privleap.privleap, which is pure stdlib -- no extra pip deps.
export PYTHONPATH="${SRC}/privleap/usr/lib/python3/dist-packages${PYTHONPATH+:${PYTHONPATH}}"

## Wrap each fuzz/fuzz_*.py harness for OSS-Fuzz's Python runtime.
## --collect-submodules pins the privleap package into the bundle explicitly
## (belt-and-braces: the harnesses import it inside atheris.instrument_imports).
for harness in fuzz/fuzz_*.py; do
  name="$(basename -- "${harness}" .py)"
  compile_python_fuzzer "${harness}" --collect-submodules=privleap
  printf 'compiled %s\n' "${name}"
done
