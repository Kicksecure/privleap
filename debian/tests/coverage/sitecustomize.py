#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

"""
Coverage bootstrap for the privleap autopkgtest. This can be very simple, since
it will only run in an autopkgtest environment where all needed dependencies
exist.
"""

import coverage
coverage.process_startup()
