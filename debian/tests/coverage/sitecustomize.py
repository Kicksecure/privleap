#!/usr/bin/python3 -Bsu

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

"""
Coverage bootstrap for the privleap autopkgtest.

privleapd, and the shim it runs actions through, are separate processes. A
coverage run that only measured the test runner would report the daemon's own
code as untested, which is the opposite of the truth. Python imports
sitecustomize automatically at interpreter startup, so putting this directory
on PYTHONPATH is what lets those child processes join the same measurement.

Inert unless COVERAGE_PROCESS_START is set, so it costs nothing when the
package is used or tested normally.
"""

import os

if os.environ.get("COVERAGE_PROCESS_START"):
    try:
        # pylint: disable=import-outside-toplevel,import-error
        # Rationale:
        #   import-outside-toplevel: importing coverage unconditionally would
        #     make every measured process pay for it.
        #   import-error: python3-coverage is a test-only dependency.
        import coverage

        coverage.process_startup()
    except Exception:
        # Coverage is optional test-only scaffolding: a failure to start it
        # (coverage absent, or process_startup erroring) must never break the
        # process being measured, least of all the privileged daemon.
        pass
