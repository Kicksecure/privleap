#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, too-many-branches, too-many-statements
# Rationale:
#   broad-exception-caught: except blocks are general error handlers.
#   too-many-branches, too-many-statements: preferring less indirection over
#     shorter functions.

"""leaprun.py - privleap client for running actions."""

import sys
import getpass
import dataclasses
from typing import cast, Union, NoReturn

# import privleap as pl
import privleap.privleap as pl

Buffer = Union[bytes, bytearray, memoryview]

@dataclasses.dataclass
class LeaprunGlobal:
    """Global variables for leaprun."""
    comm_session: pl.PrivleapSession | None = None

def cleanup_and_exit(exit_code: int) -> NoReturn:
    """Ensures any active session is closed, then exits."""
    if LeaprunGlobal.comm_session is not None:
        LeaprunGlobal.comm_session.close_session()
    sys.exit(exit_code)

def print_usage() -> NoReturn:
    """Prints usage information."""
    print("""leaprun <signal_name>

    signal_name : The name of the signal that leap should send. Sending a
                  signal with a particular name will request privleapd to
                  trigger an action of the same name.""")
    cleanup_and_exit(1)

def generic_error(error_msg: str) -> NoReturn:
    """Prints an error, then cleans up and exits."""
    print("ERROR: " + error_msg, file=sys.stderr)
    cleanup_and_exit(1)

def unexpected_msg_error(comm_msg: pl.PrivleapMsg) -> NoReturn:
    """Alerts about an unexpected message type being received from the
    server."""
    print("ERROR: privleapd returned unexpected message as follows:",
          file=sys.stderr)
    print(comm_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)

def main() -> NoReturn:
    """Main function."""
    if len(sys.argv) != 2:
        print_usage()

    signal_name: str = sys.argv[1]
    try:
        # Yes, we are explicitly stating the user's username here. This is not
        # to identify ourselves to the server, but rather to actually open the
        # right socket. privleapd provides a different socket for each user,
        # and sets each socket's permissions to only allow a user to open the
        # socket assigned to them. The only socket we can connect to is the one
        # matching our username, thus we pass the username so that we open a
        # socket that we actually *can* open. This authenticates us as a
        # side-effect, but the authentication is not dependent on us telling the
        # truth here, so there isn't a vulnerability here.
        LeaprunGlobal.comm_session = pl.PrivleapSession(getpass.getuser())
    except Exception:
        generic_error("Could not connect to privleapd!")

    assert LeaprunGlobal.comm_session is not None

    try:
        signal_msg: pl.PrivleapCommClientSignalMsg \
            = pl.PrivleapCommClientSignalMsg(signal_name)
    except Exception:
        generic_error("Signal name '" + signal_name + "' is invalid!")

    try:
        # noinspection PyUnboundLocalVariable
        LeaprunGlobal.comm_session.send_msg(signal_msg)
    except Exception:
        generic_error(
            "Could not request privleapd to run action '" + signal_name + "'!")

    try:
        comm_msg: pl.PrivleapMsg \
            | pl.PrivleapCommServerResultStdoutMsg \
            | pl.PrivleapCommServerResultStderrMsg \
            | pl.PrivleapCommServerResultExitcodeMsg \
            = LeaprunGlobal.comm_session.get_msg()
    except Exception:
        generic_error("privleapd didn't return a valid response!")

    # PyCharm can't figure out that comm_msg is always defined from here on out.
    # noinspection PyUnboundLocalVariable
    if isinstance(comm_msg, pl.PrivleapCommServerUnauthorizedMsg):
        generic_error(
            "You are unauthorized to run action '" + signal_name + "'.")
    elif isinstance(comm_msg, pl.PrivleapCommServerTriggerErrorMsg):
        generic_error(
            "An error was encountered launching action '" + signal_name + "'.")
    elif isinstance(comm_msg, pl.PrivleapCommServerTriggerMsg):
        while True:
            try:
                comm_msg = LeaprunGlobal.comm_session.get_msg()
            except Exception:
                generic_error(
                    ("Action triggered, but privleapd closed the connection "
                     "before sending all output!"))

            # Useless asserts needed to get PyCharm to understand what's
            # happening here
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
                exit_code = int(comm_msg.exit_code)
                cleanup_and_exit(exit_code)
            else:
                # noinspection PyUnboundLocalVariable
                unexpected_msg_error(comm_msg)

    else:
        # noinspection PyUnboundLocalVariable
        unexpected_msg_error(comm_msg)

if __name__ == "__main__":
    main()
