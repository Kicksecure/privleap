#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# leapctl.py - privleapd client for controlling available comm sockets.

# from privleap import *
from privleap.privleap import *
import sys
import pwd

def print_usage():
    print("""leapctl <--create|--destroy> <username>

    username : The name of the user account to create or destroy a
               communication socket of.
    --create : Specifies that leapctl should request a communication socket to
               be created for the specified user.
    --destroy : Specifies that leapctl should request a communication socket
                to be destroyed for the specified user.""")
    sys.exit(1)

def generic_error(error_msg):
    print("ERROR: " + error_msg, file=sys.stderr)
    sys.exit(1)

def unexpected_msg_error(control_msg):
    print("ERROR: privleapd returned unexpected message as follows:",
          file=sys.stderr)
    print(control_msg, file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print_usage()

    control_action = sys.argv[1]
    control_user = sys.argv[2]

    if control_action != "--create" and control_action != "--destroy":
        print_usage()

    user_list = [pw[0] for pw in pwd.getpwall()]
    if not control_user in user_list:
        generic_error("Specified user does not exist.")

    try:
        control_session = PrivleapSession("", is_control_session = True)
    except:
        generic_error("Could not connect to privleapd!")

    if control_action == "--create":
        try:
            # noinspection PyUnboundLocalVariable
            control_session.send_msg(PrivleapControlClientCreateMsg(control_user))
        except:
            generic_error("Could not request privleapd to create a comm socket!")

        try:
            control_msg = control_session.get_msg()
        except:
            generic_error("privleapd forcibly closed the connection!")

        # noinspection PyUnboundLocalVariable
        if type(control_msg) == PrivleapControlServerOkMsg:
            print("Comm socket created for user '" + control_user + "'.")
            sys.exit(0)
        elif type(control_msg) == PrivleapControlServerErrorMsg:
            generic_error("privleapd encountered an error while creating a comm socket for user '" + control_user + "'!")
        elif type(control_msg) == PrivleapControlServerExistsMsg:
            print("Comm socket already exists for user '" + control_user + "'.")
            sys.exit(0)
        else:
            unexpected_msg_error(control_msg)

    else:
        try:
            # noinspection PyUnboundLocalVariable
            control_session.send_msg(PrivleapControlClientDestroyMsg(control_user))
        except:
            generic_error("Could not request privleapd to destroy a comm socket!")

        try:
            control_msg = control_session.get_msg()
        except:
            generic_error("privleapd forcibly closed the connection!")

        # noinspection PyUnboundLocalVariable
        if type(control_msg) == PrivleapControlServerOkMsg:
            print("Comm socket destroyed for user '" + control_user + "'.")
            sys.exit(0)
        elif type(control_msg) == PrivleapControlServerErrorMsg:
            generic_error("privleapd encountered an error while destroying a comm socket for user '" + control_user + "'!")
        elif type(control_msg) == PrivleapControlServerNouserMsg:
            print("Comm socket does not exist for user '" + control_user + "'.")
            sys.exit(0)
        else:
            unexpected_msg_error(control_msg)

if __name__ == "__main__":
    main()
