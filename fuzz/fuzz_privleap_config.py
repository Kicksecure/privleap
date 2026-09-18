#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (ClusterFuzzLite) harness for privleap's config-file CONTENT parser
(privleap.PrivleapCommon.parse_config_file). Config files live in root-owned
conf.d directories, so this is not an unprivileged-client surface, but a
malformed config must fail CLOSED -- return an error string -- rather than crash
the daemon on load or reload. This harness asserts the parser returns its
declared ConfigData tuple or an error string for any input, never raising: an
uncaught exception here is a daemon-startup / reload DoS.

parse_config_file first gates on the file's ownership/mode (a separate concern,
tested in config_test.py); this harness patches that gate open so the fuzzer
explores the line-by-line PARSER, and feeds the input as valid UTF-8 so the
target is the parser, not the file's text decode.
"""

import atheris
import os
import sys
import tempfile
from pathlib import Path

with atheris.instrument_imports():
    from privleap.privleap import PrivleapCommon

## Focus the fuzzer on the content parser, not the ownership/mode gate.
PrivleapCommon.check_secure_file_permissions = staticmethod(  # type: ignore[method-assign]
    lambda *args, **kwargs: True
)


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 16)
    handle_fd, path = tempfile.mkstemp(suffix=".conf")
    try:
        with os.fdopen(handle_fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        result = PrivleapCommon.parse_config_file(Path(path))
        ## Declared return type: a ConfigData tuple on success, or an error
        ## string. Anything else -- or an exception -- is a finding.
        if not isinstance(result, (tuple, str)):
            raise RuntimeError(
                "parse_config_file returned %r" % (result,)
            )
    finally:
        os.unlink(path)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
