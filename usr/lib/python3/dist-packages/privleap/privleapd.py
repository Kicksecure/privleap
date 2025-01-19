#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# privleapd.py - privleap background process.

# from privleap import *
from privleap.privleap import *
import sys
import shutil
import re
import select
from threading import Thread
import os
import pwd
import grp
import subprocess
import traceback

class PrivleapdGlobal:
    config_dir = "/etc/privleap/conf.d"
    action_list = list()
    socket_list = list()

def handle_control_session(control_socket: PrivleapSocket):
    try:
        control_session = control_socket.get_session()
        control_msg = control_session.get_msg()
    except Exception:
        print("handle_control_session: could not start session with client")
        print(traceback.format_exc())
        return

    if type(control_msg) == PrivleapControlClientCreateMsg:
        for sock in PrivleapdGlobal.socket_list:
            if sock.user_name == control_msg.user_name:
                # User already has an open socket
                try:
                    control_session.send_msg(PrivleapControlServerExistsMsg())
                except Exception:
                    print("handle_control_session: handling CREATE, could not send EXISTS")
                    print(traceback.format_exc())
                print("handle_control_session: handled CREATE message for user '" + control_msg.user_name + "', socket already exists")
                return

        user_list = [pw[0] for pw in pwd.getpwall()]
        if not control_msg.user_name in user_list:
            try:
                control_session.send_msg(PrivleapControlServerErrorMsg())
            except Exception:
                print("handle_control_session: handling CREATE, could not send ERROR")
                print(traceback.format_exc())
            print("handle_control_session: User '" + control_msg.user_name + "' does not exist")

        try:
            comm_socket = PrivleapSocket(PrivleapSocketType.COMMUNICATION, control_msg.user_name)
            PrivleapdGlobal.socket_list.append(comm_socket)
            try:
                control_session.send_msg(PrivleapControlServerOkMsg())
            except Exception:
                print("handle_control_session: handling CREATE, could not send OK")
                print(traceback.format_exc())
            print("handle_control_session: handled CREATE message for user '" + control_msg.user_name + "', socket created")
        except Exception:
            # TODO: This should never happen, should this really be just
            #  a warning?
            print("WARNING: Failed to create socket for user '" + control_msg.user_name + "'!", file=sys.stderr)
            print(traceback.format_exc())
            try:
                control_session.send_msg(PrivleapControlServerErrorMsg())
            except Exception:
                print("handle_control_session: handling CREATE, could not send ERROR")
                print(traceback.format_exc())

    elif type(control_msg) == PrivleapControlClientDestroyMsg:
        found_user = False
        remove_sock_idx = -1
        for sock_idx, sock in enumerate(PrivleapdGlobal.socket_list):
            if sock.user_name == control_msg.user_name:
                socket_path = PrivleapCommon.comm_path + "/" + control_msg.user_name
                if os.path.exists(socket_path):
                    try:
                        os.remove(socket_path)
                    except Exception:
                        # Probably just a TOCTOU issue, i.e. someone already
                        # removed the socket. Most likely caused by the user
                        # fiddling with things, no big deal.
                        print("handle_control_session: handling DESTROY, no socket to delete at '" + socket_path + "'")
                        print(traceback.format_exc())
                remove_sock_idx = sock_idx
                found_user = True
                break

        if found_user:
            PrivleapdGlobal.socket_list.pop(remove_sock_idx)
            try:
                control_session.send_msg(PrivleapControlServerOkMsg())
            except Exception:
                print("handle_control_session: handling DESTROY, could not send OK")
                print(traceback.format_exc())
            print("handle_control_session: handled DESTROY message for user '" + control_msg.user_name + "', socket deleted")
        else:
            try:
                control_session.send_msg(PrivleapControlServerNouserMsg())
            except Exception:
                print("handle_control_session: handling DESTROY, could not send NOUSER")
                print(traceback.format_exc())
            print("handle_control_session: handled DESTROY message for user '" + control_msg.user_name + "', socket did not exist")
    else:
        print("CRITICAL ERROR: privleapd mis-parsed a control command from the client!")
        sys.exit(2)

    control_session.close_session()

def handle_comm_session(comm_socket):
    try:
        comm_session = comm_socket.get_session()
        comm_msg = comm_session.get_msg()
    except Exception:
        print("handle_comm_session: could not start session with client")
        print(traceback.format_exc())
        return

    if type(comm_msg) != PrivleapCommClientSignalMsg:
        # Illegal message, a SIGNAL needs to be the first message.
        comm_session.close_session()
        print("handle_comm_session: Did not read SIGNAL as first message, forcibly closed connection.")
        return

    signal_name = comm_msg.signal_name
    desired_action = None
    for action in PrivleapdGlobal.action_list:
        if action.action_name == signal_name:
            desired_action = action
            break

    if desired_action is None:
        # No such action, send back UNAUTHORIZED since we don't want to leak
        # the list of available actions to the client.
        try:
            comm_session.send_msg(PrivleapCommServerUnauthorizedMsg())
        except Exception:
            print("handle_comm_session: Could not send UNAUTHORIZED")
            print(traceback.format_exc())

        comm_session.close_session()
        print("handle_comm_session: Could not find action '" + signal_name + "'")
        return

    if desired_action.auth_user is not None:
        # Action exists but can only be run by certain users.
        if desired_action.auth_user != comm_session.user_name:
            # User is not authorized to run this action.
            try:
                comm_session.send_msg(PrivleapCommServerUnauthorizedMsg())
            except Exception:
                print("handle_comm_session: Could not send UNAUTHORIZED")
                print(traceback.format_exc())

            comm_session.close_session()
            print("handle_comm_session: User is not authorized to run action '" + desired_action.action_name + "'")
            return

    if desired_action.auth_group is not None:
        # Action exists but can only be run by certain groups.
        # We need to get the list of groups this user is a member of to
        # determine whether they are authorized or not.
        user_gid = grp.getgrnam(comm_session.user_name)[2]
        group_list = [grp.getgrgid(gid)[0] for gid in os.getgrouplist(comm_session.user_name, user_gid)]
        found_matching_group = False
        for group in group_list:
            if group == desired_action.auth_group:
                found_matching_group = True
                break

        if not found_matching_group:
            # User is not in the group authorized to run this action.
            try:
                comm_session.send_msg(PrivleapCommServerUnauthorizedMsg())
            except Exception:
                print("handle_comm_session: Could not send UNAUTHORIZED")
                print(traceback.format_exc())

            comm_session.close_session()
            print("handle_comm_session: User is not in a group authorized to run action '" + desired_action.action_name + "'")
            return

    # TODO: Add identity verification here in the future.

    # If we get this far, the user is authorized. Run the action.
    action_process = subprocess.Popen(['/usr/bin/bash', '-c', desired_action.action_command], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    print("handle_comm_session: Triggered action '" + desired_action.action_name + "'")
    try:
        comm_session.send_msg(PrivleapCommServerTriggerMsg(desired_action.action_name))
    except Exception:
        # Client already disconnected. At this point the action is already
        # running, and there's not any point in waiting for the process's stdout
        # and stderr, so the thread can end here.
        print("handle_comm_session: action triggered, but could not send TRIGGER")
        print(traceback.format_exc())
        return

    # Wait for the process to finish up, and send the stdout, stderr, and exit
    # code from it.
    action_output = action_process.communicate()
    print("handle_comm_session: Action '" + desired_action.action_name + "' completed")
    try:
        comm_session.send_msg(PrivleapCommServerResultStdoutMsg(desired_action.action_name, action_output[0]))
    except Exception:
        print("handle_comm_session: action triggered, but could not send RESULT_STDOUT")
        print(traceback.format_exc())

    try:
        comm_session.send_msg(PrivleapCommServerResultStderrMsg(desired_action.action_name, action_output[1]))
    except Exception:
        print("handle_comm_session: action triggered, but could not send RESULT_STDERR")
        print(traceback.format_exc())

    try:
        comm_session.send_msg(PrivleapCommServerResultExitcodeMsg(desired_action.action_name, action_process.returncode))
    except Exception:
        print("handle_comm_session: action triggered, but could not send RESULT_EXITCODE")
        print(traceback.format_exc())

def main():
    # Ensure that there aren't two servers running at once
    running_privleapd_pid_list = subprocess.run(
        ['pgrep', 'privleapd'], capture_output = True
    ).stdout.decode("utf-8").split("\n")
    for pid_idx, pid in enumerate(running_privleapd_pid_list):
        if pid == "":
            running_privleapd_pid_list.pop(pid_idx)
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
    if os.path.exists(PrivleapCommon.state_dir):
        try:
            shutil.rmtree(PrivleapCommon.state_dir)
        except:
            print("ERROR: Could not delete '" + PrivleapCommon.state_dir + "'!",
                  file=sys.stderr)
            sys.exit(1)

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
        except Exception:
            print("ERROR: Failed to parse config file '" + config_file.path + "'!",
                  file=sys.stderr)
            print(traceback.format_exc())
            sys.exit(1)

    # Create the directories for the sockets
    if not os.path.exists(PrivleapCommon.state_dir):
        try:
            os.makedirs(PrivleapCommon.state_dir)
        except:
            print("ERROR: Cannot create '" + PrivleapCommon.state_dir + "'!",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print("ERROR: '" + PrivleapCommon.state_dir + "' should not exist yet, but does!",
              file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(PrivleapCommon.comm_path):
        try:
            os.makedirs(PrivleapCommon.comm_path)
        except:
            print("ERROR: Cannot create '" + PrivleapCommon.comm_path + "'!",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print("ERROR: '" + PrivleapCommon.comm_path + "' should not exist yet, but does!",
              file=sys.stderr)
        sys.exit(1)

    # Open the control socket and enter the main loop. This loop will watch for
    # and accept connections as needed, spawning threads to handle each
    # individual comm connection. Control connections are handled in the main
    # thread since they aren't a DoS risk, and running two control sessions at
    # once could be dangerous.
    try:
        control_socket = PrivleapSocket(PrivleapSocketType.CONTROL)
    except Exception:
        print("ERROR: Failed to open control socket!", file=sys.stderr)
        print(traceback.format_exc())
        sys.exit(1)

    PrivleapdGlobal.socket_list.append(control_socket)

    while True:
        ready_socket_list = select.select([sock_obj.backend_socket for sock_obj in PrivleapdGlobal.socket_list], [], [])
        for ready_socket in ready_socket_list[0]:
            ready_sock_obj = None
            for sock_obj in PrivleapdGlobal.socket_list:
                if sock_obj.backend_socket == ready_socket:
                    ready_sock_obj = sock_obj
                    break
            if ready_sock_obj is None:
                print("CRITICAL ERROR: privleapd lost track of a socket!",
                      file=sys.stderr)
                sys.exit(1)
            if ready_sock_obj.socket_type == PrivleapSocketType.CONTROL:
                handle_control_session(ready_sock_obj)
            else:
                comm_thread = Thread(target = handle_comm_session, args = [ready_sock_obj])
                comm_thread.run()

if __name__ == "__main__":
    main()
