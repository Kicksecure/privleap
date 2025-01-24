#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# leaprun.py - privleap client for running actions.

# from privleap import *
from privleap.privleap import *
import sys
import getpass
from typing import cast
from typing import Union

Buffer = Union[bytes, bytearray, memoryview]

class LeaprunGlobal:
    comm_session: PrivleapSession | None = None

def cleanup_and_exit(exit_code: int) -> None:
    if LeaprunGlobal.comm_session is not None:
        LeaprunGlobal.comm_session.close_session()
    sys.exit(exit_code)

def print_usage() -> None:
    print("""leaprun <signal_name>

    signal_name : The name of the signal that leap should send. Sending a
                  signal with a particular name will request privleapd to
                  trigger an action of the same name.""")
    cleanup_and_exit(1)

def generic_error(error_msg: str) -> None:
    print("ERROR: " + error_msg, file=sys.stderr)
    cleanup_and_exit(1)

def unexpected_msg_error(comm_msg: PrivleapMsg) -> None:
    print("ERROR: privleapd returned unexpected message as follows:",
          file=sys.stderr)
    print(comm_msg.serialize(), file=sys.stderr)
    cleanup_and_exit(1)

def main() -> None:
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
        LeaprunGlobal.comm_session = PrivleapSession(getpass.getuser())
    except:
        generic_error("Could not connect to privleapd!")

    assert LeaprunGlobal.comm_session is not None

    try:
        signal_msg: PrivleapCommClientSignalMsg = PrivleapCommClientSignalMsg(signal_name)
    except:
        generic_error("Signal name '" + signal_name + "' is invalid!")

    try:
        # noinspection PyUnboundLocalVariable
        LeaprunGlobal.comm_session.send_msg(signal_msg)
    except:
        generic_error("Could not request privleapd to run action '" + signal_name + "'!")

    try:
        comm_msg: PrivleapMsg | PrivleapCommServerResultStdoutMsg | PrivleapCommServerResultStderrMsg | PrivleapCommServerResultExitcodeMsg = LeaprunGlobal.comm_session.get_msg()
    except:
        generic_error("privleapd didn't return a valid response!")

    # noinspection PyUnboundLocalVariable
    if type(comm_msg) == PrivleapCommServerUnauthorizedMsg:
        generic_error("You are unauthorized to run action '" + signal_name + "'.")
    elif type(comm_msg) == PrivleapCommServerTriggerErrorMsg:
        generic_error("An error was encountered launching action '" + signal_name + "'.")
    elif type(comm_msg) == PrivleapCommServerTriggerMsg:
        while True:
            try:
                comm_msg = LeaprunGlobal.comm_session.get_msg()
            except:
                generic_error("Action triggered, but privleapd closed the connection before sending all output!")

            # Useless asserts needed to get PyCharm to understand what's
            # happening here
            if type(comm_msg) == PrivleapCommServerResultStdoutMsg:
                _ = sys.stdout.buffer.write(cast(Buffer, comm_msg.stdout_bytes))
            elif type(comm_msg) == PrivleapCommServerResultStderrMsg:
                _ = sys.stderr.buffer.write(cast(Buffer, comm_msg.stderr_bytes))
            elif type(comm_msg) == PrivleapCommServerResultExitcodeMsg:
                assert comm_msg.exit_code is not None
                exit_code = int(comm_msg.exit_code)
                cleanup_and_exit(exit_code)
            else:
                unexpected_msg_error(comm_msg)

    else:
        unexpected_msg_error(comm_msg)

if __name__ == "__main__":
    main()
