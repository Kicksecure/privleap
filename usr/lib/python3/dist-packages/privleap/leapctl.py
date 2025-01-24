#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# leapctl.py - privleapd client for controlling available comm sockets.

# from privleap import *
from privleap.privleap import *
import sys
import pwd
import re

class LeapctlGlobal:
    control_session: PrivleapSession | None = None

def cleanup_and_exit(exit_code: int) -> None:
    if LeapctlGlobal.control_session is not None:
        LeapctlGlobal.control_session.close_session()
    sys.exit(exit_code)

def print_usage() -> None:
    print("""leapctl <--create|--destroy> <user>

    user : The username or UID of the user account to create or destroy a
           communication socket for.
    --create : Specifies that leapctl should request a communication socket to
               be created for the specified user.
    --destroy : Specifies that leapctl should request a communication socket
                to be destroyed for the specified user.""")
    cleanup_and_exit(1)

def generic_error(error_msg: str) -> None:
    print("ERROR: " + error_msg, file=sys.stderr)
    cleanup_and_exit(1)

def unexpected_msg_error(control_msg: PrivleapMsg) -> None:
    print("ERROR: privleapd returned unexpected message as follows:",
          file=sys.stderr)
    print(control_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)

def main() -> None:
    if len(sys.argv) != 3:
        print_usage()

    control_action: str = sys.argv[1]
    control_user: str = sys.argv[2]

    # Try to parse the username as a UID, this is needed for systemd
    # compatibility
    uid_regex: re.Pattern[str] = re.compile(r"\d+")
    if uid_regex.match(control_user):
        control_uid: int = int(control_user)
        try:
            user_info: pwd.struct_passwd = pwd.getpwuid(control_uid)
            control_user = user_info.pw_name
        except:
            generic_error("Specified user does not exist.")

    if control_action != "--create" and control_action != "--destroy":
        print_usage()

    if not PrivleapCommon.validate_id(control_user, PrivleapValidateType.USER_GROUP_NAME):
        generic_error("User name '" + control_user + "' is invalid!")

    user_list: list[str] = [pw.pw_name for pw in pwd.getpwall()]
    if not control_user in user_list:
        generic_error("Specified user does not exist.")

    try:
        LeapctlGlobal.control_session = PrivleapSession("", is_control_session = True)
    except:
        generic_error("Could not connect to privleapd!")

    assert LeapctlGlobal.control_session is not None

    if control_action == "--create":
        try:
            # noinspection PyUnboundLocalVariable
            LeapctlGlobal.control_session.send_msg(PrivleapControlClientCreateMsg(control_user))
        except:
            generic_error("Could not request privleapd to create a comm socket!")

        try:
            control_msg: PrivleapMsg = LeapctlGlobal.control_session.get_msg()
        except:
            generic_error("privleapd didn't return a valid response!")

        # noinspection PyUnboundLocalVariable
        if type(control_msg) == PrivleapControlServerOkMsg:
            print("Comm socket created for user '" + control_user + "'.")
            cleanup_and_exit(0)
        elif type(control_msg) == PrivleapControlServerControlErrorMsg:
            generic_error("privleapd encountered an error while creating a comm socket for user '" + control_user + "'!")
        elif type(control_msg) == PrivleapControlServerExistsMsg:
            print("Comm socket already exists for user '" + control_user + "'.")
            cleanup_and_exit(0)
        else:
            unexpected_msg_error(control_msg)

    else:
        try:
            # noinspection PyUnboundLocalVariable
            LeapctlGlobal.control_session.send_msg(PrivleapControlClientDestroyMsg(control_user))
        except:
            generic_error("Could not request privleapd to destroy a comm socket!")

        try:
            control_msg = LeapctlGlobal.control_session.get_msg()
        except:
            generic_error("privleapd didn't return a valid response!")

        # noinspection PyUnboundLocalVariable
        if type(control_msg) == PrivleapControlServerOkMsg:
            print("Comm socket destroyed for user '" + control_user + "'.")
            cleanup_and_exit(0)
        elif type(control_msg) == PrivleapControlServerControlErrorMsg:
            generic_error("privleapd encountered an error while destroying a comm socket for user '" + control_user + "'!")
        elif type(control_msg) == PrivleapControlServerNouserMsg:
            print("Comm socket does not exist for user '" + control_user + "'.")
            cleanup_and_exit(0)
        else:
            unexpected_msg_error(control_msg)

if __name__ == "__main__":
    main()
