#!/usr/bin/python3 -su

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught
# Rationale:
#   broad-exception-caught: except blocks are intended to catch all possible
#     exceptions in each instance to ensure the process exits with a special
#     exit code in these instances.

"""shim.py - PAM integration shim for privleap. This exists to allow privleap
actions to integrate seamlessly with PAM, allowing each action to have
environment variables and umask customized by PAM without conflicting with other
actions that may be starting simultaneously. Originally this logic was
implemented as part of privleapd itself, but because umask changes are applied
at the process level (not the thread level), PAM was modifying the umask for
privleapd as a whole, which could cause issues. This shim provides a layer of
separation between privleapd and PAM."""

import sys
import pwd
import grp
import os
import subprocess
from pathlib import Path
from typing import Any

import PAM  # type: ignore

if len(sys.argv) < 5:
    sys.exit(255)

calling_user: str = sys.argv[1]
target_user: str = sys.argv[2]
target_group: str = sys.argv[3]
init_umask: str = sys.argv[4]
command_arr: list[str] = sys.argv[5:]

try:
    target_user_info: pwd.struct_passwd = pwd.getpwnam(target_user)
    _: Any = pwd.getpwnam(target_user)
    _ = grp.getgrnam(target_group)
except Exception:
    sys.exit(255)

## privleapd uses a restrictive umask internally, but individual processes are
## expected to use a PAM-provided umask if set in PAM, or the default umask
## originally set on the privleapd process by systemd if no umask is set by
## PAM. We restore the umask from before privleapd locks its own umask down
## here. PAM can override this later if desirable.
try:
    init_umask_int: int = int(init_umask)
except Exception:
    sys.exit(255)
os.umask(init_umask_int)

pam_obj: Any = PAM.pam()
pam_obj.start("privleapd")
pam_obj.set_item(PAM.PAM_USER, calling_user)
pam_obj.set_item(PAM.PAM_RUSER, calling_user)
try:
    pam_obj.acct_mgmt()
except PAM.error as e:
    if e.args[1] == PAM.PAM_NEW_AUTHTOK_REQD:
        pass
    else:
        sys.exit(255)
pam_obj.set_item(PAM.PAM_USER, target_user)
pam_obj.setcred(PAM.PAM_REINITIALIZE_CRED)
try:
    pam_obj.open_session()
except Exception:
    pam_obj.setcred(PAM.PAM_DELETE_CRED | PAM.PAM_SILENT)
    sys.exit(255)
pam_env_list: list[str] = pam_obj.getenvlist()

action_env: dict[str, str] = os.environ.copy()
action_env["HOME"] = target_user_info.pw_dir
action_env["LOGNAME"] = target_user_info.pw_name
action_env["SHELL"] = "/usr/bin/bash"
action_env["PWD"] = target_user_info.pw_dir
action_env["USER"] = target_user_info.pw_name
for env_var in pam_env_list:
    env_var_parts: list[str] = env_var.split("=", 1)
    action_env[env_var_parts[0]] = env_var_parts[1]

target_cwd: str = target_user_info.pw_dir
if not Path(target_cwd).is_dir():
    target_cwd = "/"

try:
    exit_code: int = subprocess.run(
        command_arr,
        stdin=subprocess.DEVNULL,
        user=target_user,
        group=target_group,
        env=action_env,
        cwd=target_cwd,
        check=False,
    ).returncode
except Exception:
    sys.exit(255)

try:
    pam_obj.close_session(0)
    pam_obj.setcred(PAM.PAM_DELETE_CRED | PAM.PAM_SILENT)
except Exception:
    sys.exit(255)

sys.exit(exit_code)
