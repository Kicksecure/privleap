#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, too-many-branches, too-many-statements, too-many-return-statements
# Rationale:
#   broad-exception-caught: except blocks are intended to catch all possible
#     exceptions in each instance to prevent server crashes.
#   too-many-branches, too-many-statements, too-many-return-statements:
#     preferring less indirection over shorter functions.

"""privleapd.py - privleap background process."""

import sys
import shutil
import select
from threading import Thread
import os
import pwd
import grp
import subprocess
import traceback
import socket
import dataclasses
from typing import Tuple, cast, SupportsIndex, IO, NoReturn

# import privleap as pl
import privleap.privleap as pl

@dataclasses.dataclass
class PrivleapdGlobal:
    """Global variables for privleapd."""
    config_dir: str = "/etc/privleap/conf.d"
    action_list: list[pl.PrivleapAction] = dataclasses.field(
        default_factory = list)
    socket_list: list[pl.PrivleapSocket] = dataclasses.field(
        default_factory = list)

def handle_control_session(control_socket: pl.PrivleapSocket) -> None:
    """Handles control socket connections, for creating or destroying comm
    sockets."""
    try:
        control_session: pl.PrivleapSession = control_socket.get_session()
    except Exception:
        print("handle_control_session: could not start session with client")
        print(traceback.format_exc())
        return

    # PyCharm apparently can't figure out this try/finally block.
    # noinspection PyUnreachableCode
    try:
        try:
            control_msg: (pl.PrivleapMsg
                | pl.PrivleapControlClientCreateMsg
                | pl.PrivleapControlClientDestroyMsg) \
                = control_session.get_msg()
        except Exception:
            print("handle_control_session: could not get message from client")
            print(traceback.format_exc())
            return

        if isinstance(control_msg, pl.PrivleapControlClientCreateMsg):
            # The PrivleapControlClientCreateMsg constructor validates the
            # username for us, so we don't have to do it again here.
            assert control_msg.user_name is not None
            for sock in PrivleapdGlobal.socket_list:
                if sock.user_name == control_msg.user_name:
                    # User already has an open socket
                    try:
                        control_session.send_msg(
                            pl.PrivleapControlServerExistsMsg())
                    except Exception:
                        print("handle_control_session: handling CREATE, could "
                              "not send EXISTS")
                        print(traceback.format_exc())
                    print("handle_control_session: handled CREATE message for "
                        "user '"
                        + control_msg.user_name
                        + "', socket already exists")
                    return

            user_list: list[str] = [pw[0] for pw in pwd.getpwall()]
            if not control_msg.user_name in user_list:
                try:
                    control_session.send_msg(
                        pl.PrivleapControlServerControlErrorMsg())
                except Exception:
                    print("handle_control_session: handling CREATE, could not "
                        "send ERROR")
                    print(traceback.format_exc())
                print("handle_control_session: User '"
                    + control_msg.user_name
                    + "' does not exist")
                return

            try:
                comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
                    pl.PrivleapSocketType.COMMUNICATION, control_msg.user_name)
                PrivleapdGlobal.socket_list.append(comm_socket)
                try:
                    control_session.send_msg(pl.PrivleapControlServerOkMsg())
                except Exception:
                    print("handle_control_session: handling CREATE, could not "
                        "send OK")
                    print(traceback.format_exc())
                print("handle_control_session: handled CREATE message for "
                    "user '"
                    + control_msg.user_name
                    + "', socket created")
                return
            except Exception:
                # TODO: This should never happen, should this really be just
                #  a warning?
                print("WARNING: Failed to create socket for user '"
                    + control_msg.user_name
                    + "'!", file=sys.stderr)
                print(traceback.format_exc())
                try:
                    control_session.send_msg(
                        pl.PrivleapControlServerControlErrorMsg())
                except Exception:
                    print("handle_control_session: handling CREATE, could not "
                        "send ERROR")
                    print(traceback.format_exc())
                return

        elif isinstance(control_msg, pl.PrivleapControlClientDestroyMsg):
            # The PrivleapControlClientDestroyMsg constructor validates the
            # username for us, so we don't have to do it again here.
            assert control_msg.user_name is not None
            remove_sock_idx: int | None = None
            for sock_idx, sock in enumerate(PrivleapdGlobal.socket_list):
                if sock.user_name == control_msg.user_name:
                    socket_path: str = (pl.PrivleapCommon.comm_path
                        + "/"
                        + control_msg.user_name)
                    if os.path.exists(socket_path):
                        try:
                            os.remove(socket_path)
                        except Exception:
                            # Probably just a TOCTOU issue, i.e. someone already
                            # removed the socket. Most likely caused by the user
                            # fiddling with things, no big deal.
                            print("handle_control_session: handling DESTROY, "
                                "failed to delete socket at '"
                                + socket_path
                                + "'")
                            print(traceback.format_exc())
                    else:
                        print("handle_control_session: handling DESTROY, no "
                            "socket to delete at '"
                            + socket_path
                            + "'")
                    remove_sock_idx = sock_idx
                    break

            if remove_sock_idx is not None:
                PrivleapdGlobal.socket_list.pop(cast(SupportsIndex,
                    remove_sock_idx))
                try:
                    control_session.send_msg(pl.PrivleapControlServerOkMsg())
                except Exception:
                    print("handle_control_session: handling DESTROY, could not "
                        "send OK")
                    print(traceback.format_exc())
                print("handle_control_session: handled DESTROY message for "
                    "user '"
                    + control_msg.user_name
                    + "', socket destroyed")
                return

            # remove_sock_idx is not None.
            try:
                control_session.send_msg(
                    pl.PrivleapControlServerNouserMsg())
            except Exception:
                print("handle_control_session: handling DESTROY, could not "
                    "send NOUSER")
                print(traceback.format_exc())
            print("handle_control_session: handled DESTROY message for "
                "user '"
                + control_msg.user_name
                + "', socket did not exist")
            return
        else:
            print("CRITICAL ERROR: privleapd mis-parsed a control command from "
                "the client!")
            sys.exit(2)

    finally:
        control_session.close_session()

def handle_comm_session(comm_socket: pl.PrivleapSocket) -> None:
    """Handles comm socket connections, for running actions."""
    try:
        comm_session: pl.PrivleapSession = comm_socket.get_session()
    except Exception:
        print("handle_comm_session: could not start session with client")
        print(traceback.format_exc())
        return

    assert comm_session.user_name is not None

    try:
        try:
            comm_msg: (pl.PrivleapMsg
                | pl.PrivleapCommClientSignalMsg) = comm_session.get_msg()
        except Exception:
            print("handle_comm_session: could not get message from client")
            print(traceback.format_exc())
            return

        if not isinstance(comm_msg, pl.PrivleapCommClientSignalMsg):
            # Illegal message, a SIGNAL needs to be the first message.
            print("handle_comm_session: Did not read SIGNAL as first message, "
                "forcibly closing connection.")
            return

        assert comm_msg.signal_name is not None

        signal_name: str = comm_msg.signal_name
        desired_action: pl.PrivleapAction | None = None
        for action in PrivleapdGlobal.action_list:
            if action.action_name == signal_name:
                desired_action = action
                break

        if desired_action is None:
            # No such action, send back UNAUTHORIZED since we don't want to leak
            # the list of available actions to the client.
            try:
                comm_session.send_msg(pl.PrivleapCommServerUnauthorizedMsg())
            except Exception:
                print("handle_comm_session: Could not send UNAUTHORIZED")
                print(traceback.format_exc())

            print("handle_comm_session: Could not find action '"
                + signal_name
                + "'")
            return

        assert desired_action.action_name is not None

        if desired_action.auth_user is not None:
            # Action exists but can only be run by certain users.
            if desired_action.auth_user != comm_session.user_name:
                # User is not authorized to run this action.
                try:
                    comm_session.send_msg(
                        pl.PrivleapCommServerUnauthorizedMsg())
                except Exception:
                    print("handle_comm_session: Could not send UNAUTHORIZED")
                    print(traceback.format_exc())

                print("handle_comm_session: User is not authorized to run "
                    "action '"
                    + desired_action.action_name
                    + "'")
                return

        if desired_action.auth_group is not None:
            # Action exists but can only be run by certain groups.
            # We need to get the list of groups this user is a member of to
            # determine whether they are authorized or not.
            user_gid: int = pwd.getpwnam(comm_session.user_name).pw_gid
            group_list: list[str] \
                = [grp.getgrgid(gid).gr_name \
                   for gid in os.getgrouplist(
                       comm_session.user_name, user_gid)]
            found_matching_group: bool = False
            for group in group_list:
                if group == desired_action.auth_group:
                    found_matching_group = True
                    break

            if not found_matching_group:
                # User is not in the group authorized to run this action.
                try:
                    comm_session.send_msg(
                        pl.PrivleapCommServerUnauthorizedMsg())
                except Exception:
                    print("handle_comm_session: Could not send UNAUTHORIZED")
                    print(traceback.format_exc())

                print("handle_comm_session: User is not in a group authorized "
                    "to run action '"
                    + desired_action.action_name
                    + "'")
                return

        # TODO: Add identity verification here in the future.

        # If we get this far, the user is authorized. Run the action.
        try:
            action_process: subprocess.Popen[bytes] = run_action(desired_action)
        except Exception:
            try:
                comm_session.send_msg(
                    pl.PrivleapCommServerTriggerErrorMsg(
                        desired_action.action_name))
            except Exception:
                print("handle_comm_session: Could not send TRIGGER_ERROR")
                print(traceback.format_exc())

            print("handle_comm_session: action '"
                + desired_action.action_name
                + "' authorized, but trigger failed")
            print(traceback.format_exc())
            return

        assert action_process.stdout is not None
        assert action_process.stderr is not None

        print("handle_comm_session: Triggered action '"
            + desired_action.action_name
            + "'")

        try:
            try:
                comm_session.send_msg(
                    pl.PrivleapCommServerTriggerMsg(desired_action.action_name))
            except Exception:
                # Client already disconnected. At this point the action is
                # already running, and there's not any point in waiting for the
                # process's stdout and stderr, so the thread can end here.
                print("handle_comm_session: action triggered, but could not "
                    "send TRIGGER")
                print(traceback.format_exc())
                return

            # Send stdout and stderr blocks in a loop.
            stdout_done: bool = False
            stderr_done: bool = False
            while not stdout_done or not stderr_done:
                ready_streams: (Tuple[list[IO[bytes]], list[IO[bytes]],
                    list[IO[bytes]]]) = select.select(
                        [action_process.stdout, action_process.stderr],
                        [],
                        [])
                if action_process.stdout in ready_streams[0]:
                    # This reads up to 1024 bytes but may read less.
                    stdio_buf: bytes = action_process.stdout.read(1024)
                    if stdio_buf == b"":
                        stdout_done = True
                    else:
                        try:
                            comm_session.send_msg(
                                pl.PrivleapCommServerResultStdoutMsg(
                                    desired_action.action_name, stdio_buf))
                        except Exception:
                            print("handle_comm_session: could not send "
                                "RESULT_STDOUT")
                            print(traceback.format_exc())
                            return
                if action_process.stderr in ready_streams[0]:
                    stdio_buf = action_process.stderr.read(1024)
                    if stdio_buf == b"":
                        stderr_done = True
                    else:
                        try:
                            comm_session.send_msg(
                                pl.PrivleapCommServerResultStderrMsg(
                                    desired_action.action_name, stdio_buf))
                        except Exception:
                            print("handle_comm_session: could not send "
                                "RESULT_STDERR")
                            print(traceback.format_exc())
                            return

            action_process.wait()

        finally:
            action_process.stdout.close()
            action_process.stderr.close()
            action_process.terminate()
            action_process.wait()

        # Process is done, send the exit code and clean up
        print("handle_comm_session: Action '"
            + desired_action.action_name
            + "' completed")

        try:
            comm_session.send_msg(
                pl.PrivleapCommServerResultExitcodeMsg(
                    desired_action.action_name, str(action_process.returncode)))
        except Exception:
            print("handle_comm_session: action triggered, but could not send "
                "RESULT_EXITCODE")
            print(traceback.format_exc())
            return

    finally:
        comm_session.close_session()

def run_action(desired_action: pl.PrivleapAction) -> subprocess.Popen[bytes]:
    # pylint: disable=consider-using-with
    # Rationale:
    #   consider-using-with: Not suitable for this use case.
    """Runs the command defined in an action."""
    # User privilege de-escalation technique inspired by
    # https://stackoverflow.com/a/6037494/19474638, using this technique since
    # it ensures the environment is also changed.
    user_info: pwd.struct_passwd = pwd.getpwnam(desired_action.target_user)
    action_env: dict[str, str] = os.environ.copy()
    action_env["HOME"] = user_info.pw_dir
    action_env["LOGNAME"] = user_info.pw_name
    action_env["PWD"] = os.getcwd()
    action_env["USER"] = user_info.pw_name
    assert desired_action.action_command is not None
    action_process: subprocess.Popen[bytes] = subprocess.Popen(
        ['/usr/bin/bash', '-c',
        desired_action.action_command],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        user = desired_action.target_user,
        group = desired_action.target_group,
        env = action_env)
    return action_process

def main() -> NoReturn:
    """Main function."""
    # Ensure that there aren't two servers running at once
    running_privleapd_pid_list: list[str] = subprocess.run(
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
        print("ERROR: This platform does not allow recursive deletion of a "
            "directory without a symlink attack vuln. Exiting.",
            file=sys.stderr)
        sys.exit(1)
    # Cleanup any sockets left behind by an old privleapd process
    if os.path.exists(pl.PrivleapCommon.state_dir):
        try:
            shutil.rmtree(pl.PrivleapCommon.state_dir)
        except Exception:
            print("ERROR: Could not delete '"
                + pl.PrivleapCommon.state_dir
                + "'!",
                file=sys.stderr)
            sys.exit(1)

    # Parse configuration directory
    for config_file in os.scandir(PrivleapdGlobal.config_dir):
        if not config_file.is_file():
            continue

        if not pl.PrivleapCommon.validate_id(config_file.path,
            pl.PrivleapValidateType.CONFIG_FILE):
            continue

        try:
            with open(config_file.path, "r", encoding = "utf-8") as f:
                action_arr: list[pl.PrivleapAction] \
                    = pl.PrivleapCommon.parse_config_file(f.read())
            PrivleapdGlobal.action_list.extend(action_arr)
        except Exception:
            print("ERROR: Failed to parse config file '"
                + config_file.path
                + "'!",
                file=sys.stderr)
            print(traceback.format_exc())
            sys.exit(1)

    # Create the directories for the sockets
    if not os.path.exists(pl.PrivleapCommon.state_dir):
        try:
            os.makedirs(pl.PrivleapCommon.state_dir)
        except Exception:
            print("ERROR: Cannot create '" + pl.PrivleapCommon.state_dir + "'!",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print("ERROR: '"
            + pl.PrivleapCommon.state_dir
            + "' should not exist yet, but does!",
            file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(pl.PrivleapCommon.comm_path):
        try:
            os.makedirs(pl.PrivleapCommon.comm_path)
        except Exception:
            print("ERROR: Cannot create '" + pl.PrivleapCommon.comm_path + "'!",
                  file=sys.stderr)
            sys.exit(1)
    else:
        print("ERROR: '"
            + pl.PrivleapCommon.comm_path
            + "' should not exist yet, but does!",
            file=sys.stderr)
        sys.exit(1)

    # Open the control socket and enter the main loop. This loop will watch for
    # and accept connections as needed, spawning threads to handle each
    # individual comm connection. Control connections are handled in the main
    # thread since they aren't a DoS risk, and running two control sessions at
    # once could be dangerous.
    try:
        control_socket: pl.PrivleapSocket \
            = pl.PrivleapSocket(pl.PrivleapSocketType.CONTROL)
    except Exception:
        print("ERROR: Failed to open control socket!", file=sys.stderr)
        print(traceback.format_exc())
        sys.exit(1)

    PrivleapdGlobal.socket_list.append(control_socket)

    while True:
        ready_socket_list: Tuple[list[IO[bytes]], list[IO[bytes]], \
            list[IO[bytes]]] \
            = select.select(
                [sock_obj.backend_socket \
                    for sock_obj in PrivleapdGlobal.socket_list],
                [],
                []
            )
        for ready_socket in ready_socket_list[0]:
            ready_sock_obj: pl.PrivleapSocket | None = None
            for sock_obj in PrivleapdGlobal.socket_list:
                if sock_obj.backend_socket == cast(socket.socket, ready_socket):
                    ready_sock_obj = sock_obj
                    break
            if ready_sock_obj is None:
                print("CRITICAL ERROR: privleapd lost track of a socket!",
                      file=sys.stderr)
                sys.exit(1)
            if ready_sock_obj.socket_type == pl.PrivleapSocketType.CONTROL:
                handle_control_session(ready_sock_obj)
            else:
                comm_thread: Thread = Thread(target = handle_comm_session,
                    args = [ready_sock_obj])
                comm_thread.start()

if __name__ == "__main__":
    main()
