#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# privleapd.py - privleap background process.

from privleap import *
import subprocess
import sys
import shutil
import re

class PrivleapdGlobal:
    config_dir = "/etc/privleap/conf.d"
    action_list = list()
    socket_list = list()

def main():
    # Ensure that there aren't two servers running at once
    running_privleapd_pid_list = subprocess.run(
        ['pgrep', 'privleapd'], capture_output = True
    ).stdout.decode("utf-8").split("\n")
    if len(running_privleapd_pid_list) > 1:
        print("ERROR: Cannot run two privleapd processes at the same time.",
              file=sys.stderr)
        sys.exit(1)

    # Ensure privleapd is running as root
    if os.geteuid() != 0:
        print("ERROR: privleapd must run as root.", file=sys.stderr)
        sys.exit(1)

    # This probably won't run anywhere but Linux, but just in case, make sure
    # we aren't opening a security hole
    if not shutil.rmtree.avoids_symlink_attacks:
        print("ERROR: This platform does not allow recursive deletion of a directory without a symlink attack vuln. Exiting.",
              file=sys.stderr)
        sys.exit(1)
    # Cleanup any sockets left behind by an old privleapd process
    shutil.rmtree(PrivleapCommon.state_dir)

    # Parse configuration directory
    filename_validate_regex = re.compile(r"[./a-zA-Z_-]+\.conf")
    for config_file in os.scandir(PrivleapdGlobal.config_dir):
        if not config_file.is_file():
            continue

        if not filename_validate_regex.match(config_file.path):
            continue

        # action_name is config file name minus the ".conf" at the end, which
        # is five characters
        action_name = config_file.name[:len(config_file.name) - 5]
        try:
            with open(config_file.path, "r") as f:
                conf_data = f.read()
            action = PrivleapAction(action_name, conf_data)
            PrivleapdGlobal.action_list.append(action)
        except:
            print("ERROR: Failed to parse config file '" + config_file.path + "'!",
                  file=sys.stderr)
            sys.exit(1)

    # Open the control socket and enter the main loop. This loop will watch for
    # and accept connections as needed, processing control connections inline
    # and spawning threads for each comm connection. Note that we handle the
    # control socket in a manner that isn't concurrency-friendly since it isn't
    # a DoS risk. If an attacker can DoS privleapd through the control socket,
    # they have root, at which point they could DoS it easier by just
    # terminating it.

    # TODO: Everything after this is still WIP.

    try:
        control_socket = PrivleapSocket(PrivleapSocketType.CONTROL)
    except:
        print("ERROR: Failed to open control socket!", file=sys.stderr)
        sys.exit(1)

    PrivleapdGlobal.socket_list.append(control_socket)

    while True:
        # FIXME: We have to listen on the comm sockets too, which this code
        #  doesn't do and can't properly do. Refactor this to use select.
        try:
            control_session = control_socket.get_session()
            control_msg = control_session.get_message()
        except:
            continue

        if type(control_msg) == PrivleapControlClientCreateMessage:
            found_user = False
            for sock in PrivleapdGlobal.socket_list:
                if sock.user_name == control_msg.user_name:
                    # User already has an open socket
                    try:
                        control_session.send_message(PrivleapControlServerExistsMessage())
                    except:
                        pass
                    found_user = True
                    break
            if not found_user:
                try:
                    comm_socket = PrivleapSocket(PrivleapSocketType.COMMUNICATION, control_msg.user_name)
                    PrivleapdGlobal.socket_list.append(comm_socket)
                    try:
                        control_session.send_message(PrivleapControlServerOkMessage())
                    except:
                        pass
                except:
                    # TODO: This should never happen, should this really be just
                    #  a warning?
                    print("WARNING: Failed to create socket for user '" + control_msg.user_name + "'!", file=sys.stderr)
                    try:
                        control_session.send_message(PrivleapControlServerErrorMessage())
                    except:
                        pass
        elif type(control_msg) == PrivleapControlClientDestroyMessage:
            found_user = False
            remove_sock_idx = -1
            for sock_idx, sock in enumerate(PrivleapdGlobal.socket_list):
                if sock.user_name == control_msg.user_name:
                    socket_path = PrivleapCommon.comm_path + "/" + control_msg.user_name
                    if os.path.exists(socket_path):
                        try:
                            os.remove(socket_path)
                        except:
                            # Probably just a TOCTOU issue, i.e. someone already
                            # removed the socket. No big deal.
                            pass
                    remove_sock_idx = sock_idx
                    break

            if found_user:
                PrivleapdGlobal.socket_list.pop(remove_sock_idx)
                try:
                    control_session.send_message(PrivleapControlServerOkMessage())
                except:
                    pass
            else:
                try:
                    control_session.send_message(PrivleapControlServerNouserMessage())
                except:
                    pass
        else:
            print("CRITICAL ERROR: privleapd mis-parsed a control command from the client!")
            sys.exit(2)

        control_session.close_session()

if __name__ == "__main__":
    main()