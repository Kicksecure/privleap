#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (ClusterFuzzLite) harness for privleap's AUTHORIZATION engine -- the
decision that gates whether a requested action runs. An action runs an
arbitrary root-configured command, so an authorization bypass here is code
execution as root: this is the crown-jewel invariant.

It fuzzes the authorized-user / authorized-group NAME lists an admin's config
supplies, builds a REAL privleapd PrivleapAction from them (exercising
normalize_user_id / normalize_group_id against the live account database), and
runs the REAL privleapd.authorize_user for the fuzzer's own uid. It then asserts
the ANTI-ACE invariant directly: a non-root caller may be AUTHORIZED for a
restricted action ONLY when it is named in the action's resolved uid list or is
a member of one of the action's resolved groups. A grant without such a rule is
raised as a finding (a crash Atheris reports).

The coverage-guided counterpart to authorizer_test.py's randomized property
matrix: Atheris mutates the name inputs guided by the coverage it observes
inside normalize_*_id and authorize_user, reaching resolution/decision branches
a blind generator rarely hits. No root, no network, no live privleapd.
"""

import os
import sys

import atheris

with atheris.instrument_imports():
    from privleap.privleap import PrivleapAction
    from privleap.privleapd import PrivleapdAuthStatus, authorize_user

import pwd  # noqa: E402  (after instrumented imports, on purpose)

## The fuzzer's own identity is the caller under test: it exists (so the
## decision is never a trivial USER_MISSING) and its real group membership is
## the ground truth the anti-ACE check compares against.
_UID: int = os.getuid()
try:
    _PW = pwd.getpwuid(_UID)
    _GROUPS = set(os.getgrouplist(_PW.pw_name, _PW.pw_gid))
except (KeyError, OSError):
    _PW = None
    _GROUPS = set()


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    if _PW is None:
        return
    fdp = atheris.FuzzedDataProvider(data)
    n_users = fdp.ConsumeIntInRange(0, 4)
    users = [fdp.ConsumeUnicodeNoSurrogates(32) for _ in range(n_users)]
    n_groups = fdp.ConsumeIntInRange(0, 4)
    groups = [fdp.ConsumeUnicodeNoSurrogates(32) for _ in range(n_groups)]

    try:
        action = PrivleapAction(
            action_name="fuzz-authz",
            action_command="echo hi",
            auth_user_ids=users or None,
            auth_group_ids=groups or None,
        )
    except ValueError:
        ## No auth lists at all, or an invalid action name: not an action the
        ## authorizer would ever see, so not an authorization finding.
        return

    status = authorize_user(action, _UID)
    if (
        status is PrivleapdAuthStatus.AUTHORIZED
        and _UID != 0
        and action.auth_restricted
    ):
        ## Anti-ACE: a grant to a non-root caller on a restricted action must be
        ## backed by a matching uid rule or a group the caller is really in.
        if _UID not in action.auth_uids and _GROUPS.isdisjoint(
            action.auth_gids
        ):
            raise RuntimeError(
                "anti-ACE violation: authorize_user granted uid %d with no "
                "matching rule; auth_uids=%r auth_gids=%r from users=%r "
                "groups=%r" % (_UID, action.auth_uids, action.auth_gids, users, groups)
            )


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
