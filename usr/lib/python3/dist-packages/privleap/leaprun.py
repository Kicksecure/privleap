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

"""leaprun.py - privleap client for running actions."""

import sys
import getpass
from typing import cast, Union, NoReturn

# import privleap as pl
import privleap.privleap as pl

Buffer = Union[bytes, bytearray, memoryview]

# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: This class just stores global variables, it needs no
#     public methods. Namespacing global variables in a class makes things
#     safer.
class LeaprunGlobal:
    """
    Global variables for leaprun.
    """

    signal_name: str | None = None
    signal_msg: pl.PrivleapCommClientSignalMsg | None = None
    comm_session: pl.PrivleapSession | None = None

def cleanup_and_exit(exit_code: int) -> NoReturn:
    """
    Ensures any active session is closed, then exits.
    """

    if LeaprunGlobal.comm_session is not None:
        LeaprunGlobal.comm_session.close_session()
    sys.exit(exit_code)

def print_usage() -> NoReturn:
    """
    Prints usage information.
    """

    print("""leaprun <signal_name>

    signal_name : The name of the signal that leap should send. Sending a
                  signal with a particular name will request privleapd to
                  trigger an action of the same name.""")
    cleanup_and_exit(1)

def generic_error(error_msg: str) -> NoReturn:
    """
    Prints an error, then cleans up and exits.
    """

    print(f"ERROR: {error_msg}", file=sys.stderr)
    cleanup_and_exit(1)

def unexpected_msg_error(comm_msg: pl.PrivleapMsg) -> NoReturn:
    """
    Alerts about an unexpected message type being received from the server.
    """

    print("ERROR: privleapd returned unexpected message as follows:",
          file=sys.stderr)
    print(comm_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)

def create_signal_msg() -> None:
    """
    Creates a signal message from a signal name.
    """

    assert LeaprunGlobal.signal_name is not None
    try:
        LeaprunGlobal.signal_msg \
            = pl.PrivleapCommClientSignalMsg(LeaprunGlobal.signal_name)
    except Exception:
        generic_error(f"Signal name {repr(LeaprunGlobal.signal_name)} is "
            "invalid!")

def start_comm_session() -> None:
    """
    Starts a comm session with the server.
    """

    try:
        # Yes, we are explicitly stating the user's username here. This is not
        # to identify ourselves to the server, but rather to actually open the
        # right socket. privleapd provides a different socket for each user,
        # and sets each socket's permissions to only allow a user to open the
        # socket assigned to them. The only socket we can connect to is the one
        # matching our username, thus we pass the username so that we open a
        # socket that we actually *can* open. This authenticates us as a
        # side-effect, but the authentication is not dependent on us telling the
        # truth, so there isn't a vulnerability here.
        LeaprunGlobal.comm_session = pl.PrivleapSession(getpass.getuser())
    except Exception:
        generic_error("Could not connect to privleapd!")

def send_signal() -> None:
    """
    Sends a signal to the server using the open comm session.
    """

    assert LeaprunGlobal.comm_session is not None
    assert LeaprunGlobal.signal_name is not None
    assert LeaprunGlobal.signal_msg is not None
    try:
        # noinspection PyUnboundLocalVariable
        LeaprunGlobal.comm_session.send_msg(LeaprunGlobal.signal_msg)
    except Exception:
        generic_error("Could not request privleapd to run action "
            f"{repr(LeaprunGlobal.signal_name)}!")

def handle_response() -> NoReturn:
    """
    Handles the signal response from the server.
    """

    assert LeaprunGlobal.comm_session is not None
    assert LeaprunGlobal.signal_name is not None
    try:
        comm_msg: pl.PrivleapMsg \
            | pl.PrivleapCommServerResultStdoutMsg \
            | pl.PrivleapCommServerResultStderrMsg \
            | pl.PrivleapCommServerResultExitcodeMsg \
            = LeaprunGlobal.comm_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    if isinstance(comm_msg, pl.PrivleapCommServerUnauthorizedMsg):
        generic_error("You are unauthorized to run action "
            f"{repr(LeaprunGlobal.signal_name)}.")
    elif isinstance(comm_msg, pl.PrivleapCommServerTriggerErrorMsg):
        generic_error("An error was encountered launching action "
            f"{repr(LeaprunGlobal.signal_name)}.")
    elif isinstance(comm_msg, pl.PrivleapCommServerTriggerMsg):
        while True:
            try:
                comm_msg = LeaprunGlobal.comm_session.get_msg()
            except Exception:
                generic_error(
                    "Action triggered, but privleapd closed the connection "
                     "before sending all output!")

            # noinspection PyUnboundLocalVariable
            if isinstance(comm_msg, pl.PrivleapCommServerResultStdoutMsg):
                # noinspection PyUnboundLocalVariable
                _ = sys.stdout.buffer.write(cast(Buffer, comm_msg.stdout_bytes))
            elif isinstance(comm_msg, pl.PrivleapCommServerResultStderrMsg):
                # noinspection PyUnboundLocalVariable
                _ = sys.stderr.buffer.write(cast(Buffer, comm_msg.stderr_bytes))
            elif isinstance(comm_msg, pl.PrivleapCommServerResultExitcodeMsg):
                # noinspection PyUnboundLocalVariable
                assert comm_msg.exit_code is not None
                cleanup_and_exit(comm_msg.exit_code)
            else:
                # noinspection PyUnboundLocalVariable
                unexpected_msg_error(comm_msg)

    else:
        # noinspection PyUnboundLocalVariable
        unexpected_msg_error(comm_msg)

def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) != 2:
        print_usage()
    LeaprunGlobal.signal_name = sys.argv[1]

    create_signal_msg()
    start_comm_session()
    send_signal()
    handle_response()

if __name__ == "__main__":
    main()
