#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,duplicate-code
# Rationale:
#   broad-exception-caught: except blocks are general error handlers.
#   duplicate-code: This is being triggered because of generic_error and
#     unexpected_error_msg, which are very similar in leapctl and leaprun but
#     can't be reasonably broken out of either due to the fact that they access
#     incompatible variants of the cleanup_and_exit function.

"""leapctl.py - privleapd client for controlling available comm sockets."""

import sys
from typing import NoReturn

# import privleap as pl

import privleap.privleap as pl


# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: This class just stores global variables, it needs no
#     public methods. Namespacing global variables in a class makes things
#     safer.
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

    print(
        """leapctl <--create|--destroy> <user>
leapctl --reload

    --create : Specifies that leapctl should request a communication socket to
               be created for the specified user account.
    --destroy : Specifies that leapctl should request a communication socket
                to be destroyed for the specified user account.
    --reload : Instructs privleapd to reload configuration without restarting.
    user : The username or UID of the user account to create or destroy a
           communication socket for."""
    )
    cleanup_and_exit(1)


def generic_error(error_msg: str, exit_int: int = 1) -> NoReturn:
    """
    Prints an error, then cleans up and exits.
    """

    print(f"ERROR: {error_msg}", file=sys.stderr)
    cleanup_and_exit(exit_int)


def unexpected_msg_error(control_msg: pl.PrivleapMsg) -> NoReturn:
    """
    Alerts about an unexpected message type being received from the server.
    """

    print(
        "ERROR: privleapd returned unexpected message as follows:",
        file=sys.stderr,
    )
    print(control_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)


def start_control_session() -> None:
    """
    Starts a control session with the server.
    """

    try:
        LeapctlGlobal.control_session = pl.PrivleapSession(
            is_control_session=True
        )
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
            pl.PrivleapControlClientCreateMsg(user_name)
        )
    except Exception:
        generic_error("Could not request privleapd to create a comm socket!")

    try:
        control_msg: pl.PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    # noinspection PyUnboundLocalVariable
    if isinstance(control_msg, pl.PrivleapControlServerOkMsg):
        print(f"Comm socket created for account {repr(user_name)}.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerControlErrorMsg):
        generic_error(
            "privleapd encountered an error while creating a comm socket "
            f"for account {repr(user_name)}!"
        )
    elif isinstance(control_msg, pl.PrivleapControlServerDisallowedUserMsg):
        generic_error(
            f"Account {repr(user_name)} is not permitted to have a comm socket!",
            2,
        )
    elif isinstance(
        control_msg,
        pl.PrivleapControlServerExpectedDisallowedUserMsg,
    ):
        print(
            f"Account {repr(user_name)} is not permitted to have a comm "
            "socket, as expected, ok."
        )
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerExistsMsg):
        print(f"Comm socket already exists for account {repr(user_name)}.")
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
            pl.PrivleapControlClientDestroyMsg(user_name)
        )
    except Exception:
        generic_error("Could not request privleapd to destroy a comm socket!")

    try:
        control_msg: pl.PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    # noinspection PyUnboundLocalVariable
    if isinstance(control_msg, pl.PrivleapControlServerOkMsg):
        print(f"Comm socket destroyed for account {repr(user_name)}.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerControlErrorMsg):
        generic_error(
            "privleapd encountered an error while destroying a comm "
            f"socket for account {repr(user_name)}!"
        )
    elif isinstance(control_msg, pl.PrivleapControlServerNouserMsg):
        print(f"Comm socket does not exist for account {repr(user_name)}.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerPersistentUserMsg):
        print(
            f"Cannot destroy socket for persistent account {repr(user_name)}."
        )
        # It is not an error to try to destroy a socket for a persistent user,
        # since this may legitimately happen if someone logs in as a user that
        # happens to be persistent in privleap's config, and then logs out.
        cleanup_and_exit(0)
    else:
        unexpected_msg_error(control_msg)


def handle_reload_request() -> NoReturn:
    """
    Requests that privleapd reload its configuration files without restarting.
    """

    assert LeapctlGlobal.control_session is not None

    try:
        LeapctlGlobal.control_session.send_msg(
            pl.PrivleapControlClientReloadMsg()
        )
    except Exception:
        generic_error("Could not request privleapd to reload configuration!")

    try:
        control_msg: pl.PrivleapMsg = LeapctlGlobal.control_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    if isinstance(control_msg, pl.PrivleapControlServerOkMsg):
        print("privleapd configuration reload successful.")
        cleanup_and_exit(0)
    elif isinstance(control_msg, pl.PrivleapControlServerControlErrorMsg):
        generic_error("privleapd failed to reload configuration!")
    else:
        unexpected_msg_error(control_msg)


def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print_usage()

    control_action: str = sys.argv[1]
    control_user: str | None = None
    if len(sys.argv) == 3:
        control_user = sys.argv[2]

    if control_action not in ("--create", "--destroy", "--reload"):
        print_usage()
    if control_action == "--reload" and control_user is not None:
        print_usage()

    if control_user is not None:
        orig_control_user = control_user
        control_user = pl.PrivleapCommon.normalize_user_id(control_user)
        # Allow a username that doesn't exist to be passed when using --destroy,
        # so if a user is deleted before their comm socket is destroyed, the
        # socket can be destroyed anyway.
        if control_user is None:
            if control_action != "--destroy":
                generic_error("Specified user account does not exist.")
            else:
                control_user = orig_control_user

    start_control_session()

    if control_action == "--create":
        assert control_user is not None
        handle_create_request(control_user)
    elif control_action == "--destroy":
        assert control_user is not None
        handle_destroy_request(control_user)
    else:
        handle_reload_request()


if __name__ == "__main__":
    main()
