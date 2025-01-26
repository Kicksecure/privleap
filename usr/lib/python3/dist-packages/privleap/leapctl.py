#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught
# Rationale:
#   broad-exception-caught: except blocks are general error handlers.

"""leapctl.py - privleapd client for controlling available comm sockets."""

import sys
import re
import pwd
from typing import NoReturn

# import privleap as pl
import privleap.privleap as pl

class LeapctlGlobal:
    """
    Global variables for leapctl.
    """

    control_session: pl.PrivleapSession | None = None

def cleanup_and_exit(exit_code: int) -> NoReturn:
    """
    Ensures any active session is closed, then exits.
    """

    if LeapctlGlobal.control_session is not None:
        LeapctlGlobal.control_session.close_session()
    sys.exit(exit_code)

def print_usage() -> NoReturn:
    """
    Prints usage information.
    """

    print("""leapctl <--create|--destroy> <user>

    user : The username or UID of the user account to create or destroy a
           communication socket for.
    --create : Specifies that leapctl should request a communication socket to
               be created for the specified user.
    --destroy : Specifies that leapctl should request a communication socket
                to be destroyed for the specified user.""")
    cleanup_and_exit(1)

def generic_error(error_msg: str) -> NoReturn:
    """
    Prints an error, then cleans up and exits.
    """

    print("ERROR: " + error_msg, file=sys.stderr)
    cleanup_and_exit(1)

def unexpected_msg_error(control_msg: pl.PrivleapMsg) -> NoReturn:
    """
    Alerts about an unexpected message type being received from the server.
    """

    print("ERROR: privleapd returned unexpected message as follows:",
        file=sys.stderr)
    print(control_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)

def normalize_username(user_id: str) -> str:
    """
    Normalizes and validates the user identity. This will convert a UID to a
      username if needed.
    """

    uid_regex: re.Pattern[str] = re.compile(r"\d+")
    user_name: str | None = None
    if uid_regex.match(user_id):
        user_uid: int = int(user_id)
        try:
            user_info: pwd.struct_passwd = pwd.getpwuid(user_uid)
            user_name = user_info.pw_name
        except Exception:
            generic_error("Specified user does not exist.")
    else:
        user_name = user_id

    if not pl.PrivleapCommon.validate_id(user_name,
        pl.PrivleapValidateType.USER_GROUP_NAME):
        generic_error("User name '" + user_name + "' is invalid!")

    user_list: list[str] = [pw.pw_name for pw in pwd.getpwall()]
    if not user_name in user_list:
        generic_error("Specified user does not exist.")

    return user_name

def start_control_session() -> None:
    """
    Starts a control session with the server.
    """

    try:
        LeapctlGlobal.control_session = pl.PrivleapSession(
            is_control_session = True)
    except Exception:
        generic_error("Could not connect to privleapd!")

def handle_create_request(user_name: str) -> NoReturn:
    """
    Requests that privleapd create a socket for the specified user, and handles
      the response to the request.
    """

    assert LeapctlGlobal.control_session is not None

    try:
        LeapctlGlobal.control_session.send_msg(
            pl.PrivleapControlClientCreateMsg(user_name))
    except Exception:
        generic_error(
            "Could not request privleapd to create a comm socket!")

    try:
        control_msg: pl.PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    # noinspection PyUnboundLocalVariable
    if isinstance(control_msg, pl.PrivleapControlServerOkMsg):
        print("Comm socket created for user '" + user_name + "'.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerControlErrorMsg):
        generic_error(
            "privleapd encountered an error while creating a comm socket "
            "for user '"
            + user_name
            + "'!")
    elif isinstance(control_msg, pl.PrivleapControlServerExistsMsg):
        print("Comm socket already exists for user '" + user_name + "'.")
        cleanup_and_exit(0)
    else:
        unexpected_msg_error(control_msg)

def handle_destroy_request(user_name: str) -> NoReturn:
    """
    Requests that privleapd destroy a socket for the specified user, and handles
      the response to the request.
    """

    assert LeapctlGlobal.control_session is not None

    try:
        # noinspection PyUnboundLocalVariable
        LeapctlGlobal.control_session.send_msg(
            pl.PrivleapControlClientDestroyMsg(user_name))
    except Exception:
        generic_error(
            "Could not request privleapd to destroy a comm socket!")

    try:
        control_msg: pl.PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    # noinspection PyUnboundLocalVariable
    if isinstance(control_msg, pl.PrivleapControlServerOkMsg):
        print("Comm socket destroyed for user '" + user_name + "'.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerControlErrorMsg):
        generic_error(
            "privleapd encountered an error while destroying a comm "
            "socket for user '"
            + user_name
            + "'!")
    elif isinstance(control_msg, pl.PrivleapControlServerNouserMsg):
        print("Comm socket does not exist for user '" + user_name + "'.")
        cleanup_and_exit(0)
    else:
        unexpected_msg_error(control_msg)

def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) != 3:
        print_usage()

    control_action: str = sys.argv[1]
    control_user: str = sys.argv[2]

    if control_action not in ("--create", "--destroy"):
        print_usage()

    control_user = normalize_username(control_user)

    start_control_session()

    if control_action == "--create":
        handle_create_request(control_user)
    else:
        handle_destroy_request(control_user)

if __name__ == "__main__":
    main()
