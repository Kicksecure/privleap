#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# leaprun.py - privleap client for running actions.

# from privleap import *
from privleap.privleap import *
import sys
import getpass

def print_usage():
    print("""leaprun <signal_name>

    signal_name : The name of the signal that leap should send. Sending a
                  signal with a particular name will request privleapd to
                  trigger an action of the same name.""")
    sys.exit(1)

def generic_error(error_msg):
    print("ERROR: " + error_msg, file=sys.stderr)
    sys.exit(1)

def unexpected_msg_error(comm_msg):
    print("ERROR: privleapd returned unexpected message as follows:",
          file=sys.stderr)
    print(comm_msg, file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print_usage()

    signal_name = sys.argv[1]
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
        comm_session = PrivleapSession(getpass.getuser())
    except:
        generic_error("Could not connect to privleapd!")

    try:
        # noinspection PyUnboundLocalVariable
        comm_session.send_message(PrivleapCommClientSignalMessage(signal_name))
    except:
        generic_error("Could not request privleapd to run action '" + signal_name + "'!")

    try:
        comm_msg = comm_session.get_message()
    except:
        generic_error("privleapd forcibly closed the connection!")

    # noinspection PyUnboundLocalVariable
    if type(comm_msg) == PrivleapCommServerUnauthorizedMessage:
        generic_error("You are unauthorized to run action '" + signal_name + "'.")
    elif type(comm_msg) == PrivleapCommServerTriggerMessage:
        exit_code = 0

        for _ in range(3):
            try:
                comm_msg = comm_session.get_message()
            except:
                generic_error("Action triggered, but privleapd closed the connection before sending all output!")

            if type(comm_msg) == PrivleapCommServerResultStdoutMessage:
                _ = sys.stdout.buffer.write(comm_msg.stdout_bytes)
            elif type(comm_msg) == PrivleapCommServerResultStderrMessage:
                _ = sys.stderr.buffer.write(comm_msg.stderr_bytes)
            elif type(comm_msg) == PrivleapCommServerResultExitcodeMessage:
                exit_code = int(comm_msg.exit_code)
            else:
                unexpected_msg_error(comm_msg)

        sys.exit(exit_code)
    else:
        unexpected_msg_error(comm_msg)

if __name__ == "__main__":
    main()