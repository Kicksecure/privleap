#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught
# Rationale:
#   broad-exception-caught: except blocks are intended to catch all possible
#     exceptions in each instance to prevent server crashes.

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
import re
from pathlib import Path
from typing import Tuple, cast, SupportsIndex, IO, NoReturn

# import privleap as pl
import privleap.privleap as pl

class PrivleapdGlobal:
    """
    Global variables for privleapd.
    """

    config_dir: Path = Path("/etc/privleap/conf.d")
    action_list: list[pl.PrivleapAction] = []
    socket_list: list[pl.PrivleapSocket] = []
    pid_file_path: Path = Path(pl.PrivleapCommon.state_dir, "pid")

def send_msg_safe(session: pl.PrivleapSession, msg: pl.PrivleapMsg) -> bool:
    """
    Sends a message to the client, gracefully handling the situation where the
      client has already closed the session.
    """

    try:
        session.send_msg(msg)
    except Exception:
        print("send_msg_safe: could not send " + msg.name)
        print(traceback.format_exc())
        return False
    return True

def handle_control_create_msg(control_session: pl.PrivleapSession,
    control_msg: pl.PrivleapControlClientCreateMsg) -> None:
    """
    Handles a CREATE control message from the client.
    """

    # The PrivleapControlClientCreateMsg constructor validates the
    # username for us, so we don't have to do it again here.
    assert control_msg.user_name is not None
    for sock in PrivleapdGlobal.socket_list:
        if sock.user_name == control_msg.user_name:
            # User already has an open socket
            print("handle_control_session: handled CREATE message for user '"
                + control_msg.user_name
                + "', socket already exists")
            send_msg_safe(
                control_session, pl.PrivleapControlServerExistsMsg())
            return

    user_list: list[str] = [pw[0] for pw in pwd.getpwall()]
    if not control_msg.user_name in user_list:
        print("handle_control_session: User '"
            + control_msg.user_name
            + "' does not exist")
        send_msg_safe(
            control_session, pl.PrivleapControlServerControlErrorMsg())
        return

    try:
        comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
            pl.PrivleapSocketType.COMMUNICATION, control_msg.user_name)
        PrivleapdGlobal.socket_list.append(comm_socket)
        print("handle_control_session: handled CREATE message for user '"
            + control_msg.user_name
            + "', socket created")
        send_msg_safe(
            control_session, pl.PrivleapControlServerOkMsg())
        return
    except Exception:
        print("WARNING: Failed to create socket for user '"
            + control_msg.user_name
            + "'!", file=sys.stderr)
        print(traceback.format_exc())
        send_msg_safe(
            control_session, pl.PrivleapControlServerControlErrorMsg())
        return

def handle_control_destroy_msg(control_session: pl.PrivleapSession,
    control_msg: pl.PrivleapControlClientDestroyMsg) -> None:
    """
    Handles a DESTROY control message from the client.
    """

    # The PrivleapControlClientDestroyMsg constructor validates the
    # username for us, so we don't have to do it again here.
    assert control_msg.user_name is not None
    remove_sock_idx: int | None = None
    for sock_idx, sock in enumerate(PrivleapdGlobal.socket_list):
        if sock.user_name == control_msg.user_name:
            socket_path: Path = Path(pl.PrivleapCommon.comm_dir,
                                     control_msg.user_name)
            if socket_path.exists():
                try:
                    socket_path.unlink()
                except Exception:
                    # Probably just a TOCTOU issue, i.e. someone already
                    # removed the socket. Most likely caused by the user
                    # fiddling with things, no big deal.
                    print("handle_control_session: handling DESTROY, failed to "
                        "delete socket at '"
                        + str(socket_path)
                        + "'")
                    print(traceback.format_exc())
            else:
                print("handle_control_session: handling DESTROY, no socket to "
                    "delete at '"
                    + str(socket_path)
                    + "'")
            remove_sock_idx = sock_idx
            break

    if remove_sock_idx is not None:
        PrivleapdGlobal.socket_list.pop(cast(SupportsIndex,
                                             remove_sock_idx))
        print("handle_control_session: handled DESTROY message for user '"
            + control_msg.user_name
            + "', socket destroyed")
        send_msg_safe(
            control_session, pl.PrivleapControlServerOkMsg())
        return

    # remove_sock_idx is not None.
    print("handle_control_session: handled DESTROY message for user '"
        + control_msg.user_name
        + "', socket did not exist")
    send_msg_safe(
        control_session, pl.PrivleapControlServerNouserMsg())
    return

def handle_control_session(control_socket: pl.PrivleapSocket) -> None:
    """
    Handles control socket connections, for creating or destroying comm sockets.
    """

    try:
        control_session: pl.PrivleapSession = control_socket.get_session()
    except Exception:
        print("handle_control_session: could not start session with client")
        print(traceback.format_exc())
        return

    try:
        control_msg: (pl.PrivleapMsg
            | pl.PrivleapControlClientCreateMsg
            | pl.PrivleapControlClientDestroyMsg)

        try:
            control_msg = control_session.get_msg()
        except Exception:
            print("handle_control_session: could not get message from client")
            print(traceback.format_exc())
            return

        if isinstance(control_msg, pl.PrivleapControlClientCreateMsg):
            handle_control_create_msg(control_session, control_msg)
        elif isinstance(control_msg, pl.PrivleapControlClientDestroyMsg):
            handle_control_destroy_msg(control_session, control_msg)
        else:
            print("CRITICAL ERROR: privleapd mis-parsed a control command from "
                "the client!")
            sys.exit(2)

    finally:
        control_session.close_session()

def run_action(desired_action: pl.PrivleapAction) -> subprocess.Popen[bytes]:
    # pylint: disable=consider-using-with
    # Rationale:
    #   consider-using-with: Not suitable for this use case.

    """
    Runs the command defined in an action.
    """

    # User privilege de-escalation technique inspired by
    # https://stackoverflow.com/a/6037494/19474638, using this technique since
    # it ensures the environment is also changed.
    user_info: pwd.struct_passwd = pwd.getpwnam(desired_action.target_user)
    action_env: dict[str, str] = os.environ.copy()
    action_env["HOME"] = user_info.pw_dir
    action_env["LOGNAME"] = user_info.pw_name
    action_env["PWD"] = user_info.pw_dir
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

def get_signal_msg(comm_session: pl.PrivleapSession) \
    -> pl.PrivleapCommClientSignalMsg | None:
    """
    Gets a SIGNAL comm message from the client. Returns None if the client tries
      to send something other than a SIGNAL message.
    """

    try:
        comm_msg = comm_session.get_msg()
    except Exception:
        print("handle_comm_session: could not get message from client")
        print(traceback.format_exc())
        return None

    if not isinstance(comm_msg, pl.PrivleapCommClientSignalMsg):
        # Illegal message, a SIGNAL needs to be the first message.
        print("handle_comm_session: Did not read SIGNAL as first message, "
            "forcibly closing connection.")
        return None

    return comm_msg

def lookup_desired_action(action_name: str, comm_session: pl.PrivleapSession) \
    -> pl.PrivleapAction | None:
    """
    Finds the privleap action corresponding to the provided action name. Returns
      None and informs the client if the action cannot be found
    """
    for action in PrivleapdGlobal.action_list:
        if action.action_name == action_name:
            return action

    # No such action, send back UNAUTHORIZED since we don't want to leak
    # the list of available actions to the client.
    send_msg_safe(comm_session, pl.PrivleapCommServerUnauthorizedMsg())
    print("handle_comm_session: Could not find action '"
        + action_name
        + "'")
    return None

def authenticate_user(action: pl.PrivleapAction,
    comm_session: pl.PrivleapSession) -> bool:
    """
    Ensures the user that requested an action to be run is authorized to run
      the requested action. Returns True if the client is authorized. Returns
      False and informs the client if the client is not authorized.
    """
    assert action.action_name is not None
    assert comm_session.user_name is not None
    if action.auth_user is not None:
        # Action exists but can only be run by certain users.
        if action.auth_user != comm_session.user_name:
            # User is not authorized to run this action.
            print("handle_comm_session: User is not authorized to run action '"
                + action.action_name
                + "'")
            send_msg_safe(comm_session, pl.PrivleapCommServerUnauthorizedMsg())
            return False

    if action.auth_group is not None:
        # Action exists but can only be run by certain groups.
        # We need to get the list of groups this user is a member of to
        # determine whether they are authorized or not.
        user_gid: int = pwd.getpwnam(comm_session.user_name).pw_gid
        group_list: list[str] = [grp.getgrgid(gid).gr_name \
            for gid in os.getgrouplist(comm_session.user_name, user_gid)]
        found_matching_group: bool = False
        for group in group_list:
            if group == action.auth_group:
                found_matching_group = True
                break

        if not found_matching_group:
            # User is not in the group authorized to run this action.
            print("handle_comm_session: User is not in a group authorized "
                "to run action '"
                + action.action_name
                + "'")
            send_msg_safe(comm_session, pl.PrivleapCommServerUnauthorizedMsg())
            return False

    # TODO: Consider adding identity verification here in the future.

    return True

def send_action_results(comm_session: pl.PrivleapSession,
    action_name: str,
    action_process: subprocess.Popen[bytes]) -> None:
    """
    Streams the stdout and stderr of the running action to the client, and sends
      the exitcode once the action is finished running.
    """

    assert action_process.stdout is not None
    assert action_process.stderr is not None
    try:
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
                    if not send_msg_safe(comm_session,
                        pl.PrivleapCommServerResultStdoutMsg(action_name,
                            stdio_buf)):
                        return
            if action_process.stderr in ready_streams[0]:
                stdio_buf = action_process.stderr.read(1024)
                if stdio_buf == b"":
                    stderr_done = True
                else:
                    if not send_msg_safe(comm_session,
                        pl.PrivleapCommServerResultStderrMsg(action_name,
                            stdio_buf)):
                        return

        action_process.wait()

    finally:
        action_process.stdout.close()
        action_process.stderr.close()
        action_process.terminate()
        action_process.wait()

    # Process is done, send the exit code and clean up
    print("handle_comm_session: Action '"
        + action_name
        + "' completed")

    send_msg_safe(comm_session, pl.PrivleapCommServerResultExitcodeMsg(
        action_name, str(action_process.returncode)))

def handle_comm_session(comm_socket: pl.PrivleapSocket) -> None:
    """
    Handles comm socket connections, for running actions.
    """

    try:
        comm_session: pl.PrivleapSession = comm_socket.get_session()
    except Exception:
        print("handle_comm_session: could not start session with client")
        print(traceback.format_exc())
        return

    assert comm_session.user_name is not None

    try:
        comm_msg: pl.PrivleapCommClientSignalMsg | None \
            = get_signal_msg(comm_session)
        if comm_msg is None:
            return

        desired_action: pl.PrivleapAction | None = lookup_desired_action(
            comm_msg.signal_name, comm_session)
        if desired_action is None:
            return
        assert desired_action.action_name is not None

        if not authenticate_user(desired_action, comm_session):
            return

        try:
            action_process: subprocess.Popen[bytes] = run_action(desired_action)
        except Exception:
            print("handle_comm_session: action '"
                + desired_action.action_name
                + "' authorized, but trigger failed")
            print(traceback.format_exc())
            send_msg_safe(comm_session, pl.PrivleapCommServerTriggerErrorMsg(
                desired_action.action_name))
            return

        print("handle_comm_session: Triggered action '"
            + desired_action.action_name
            + "'")

        if not send_msg_safe(comm_session,
            pl.PrivleapCommServerTriggerMsg(desired_action.action_name)):
            # Client already disconnected. At this point the action is
            # already running, and there's not any point in waiting for the
            # process's stdout and stderr, so the thread can end here.
            return

        send_action_results(comm_session, desired_action.action_name,
            action_process)

    finally:
        comm_session.close_session()

def ensure_running_as_root() -> None:
    """
    Ensures the server is running as root. privleapd cannot function when
      running as a user as it may have to execute commands as root.
    """

    if os.geteuid() != 0:
        print("ERROR: privleapd must run as root.", file=sys.stderr)
        sys.exit(1)

def verify_not_running_twice() -> None:
    """
    Ensures that two simultaneous instances of privleapd are not running at the
      same time.
    """

    if not PrivleapdGlobal.pid_file_path.exists():
        return

    with open(PrivleapdGlobal.pid_file_path, "r", encoding = "utf-8") \
        as pid_file:
        old_pid_str: str = pid_file.read().strip()
        old_pid_validate_regex: re.Pattern[str] = re.compile(r"\d+\Z")
        if not old_pid_validate_regex.match(old_pid_str):
            return

        old_pid: int = int(old_pid_str)
        # Send signal 0 to check for existence, this will raise an OSError if
        # the process doesn't exist
        try:
            os.kill(old_pid, 0)
            print("ERROR: Cannot run two privleapd processes at the "
                "same time.",
                file = sys.stderr)
            sys.exit(1)
        except OSError:
            return
        except Exception:
            print("ERROR: Could not check for simultaneously running privleapd"
                "process!",
                file = sys.stderr)
            sys.exit(1)

def cleanup_old_state_dir() -> None:
    """
    Cleans up the old state directory left behind by a previous privleapd
      instance.
    """

    # This probably won't run anywhere but Linux, but just in case, make sure
    # we aren't opening a security hole
    if not shutil.rmtree.avoids_symlink_attacks:
        print("ERROR: This platform does not allow recursive deletion of a "
            "directory without a symlink attack vuln. Exiting.",
            file=sys.stderr)
        sys.exit(1)
    # Cleanup any sockets left behind by an old privleapd process
    if pl.PrivleapCommon.state_dir.exists():
        try:
            shutil.rmtree(pl.PrivleapCommon.state_dir)
        except Exception:
            print("ERROR: Could not delete '"
                + str(pl.PrivleapCommon.state_dir)
                + "'!",
                file=sys.stderr)
            sys.exit(1)

def parse_config_files() -> None:
    """
    Parses all config files under /etc/privleap/conf.d.
    """

    for config_file in PrivleapdGlobal.config_dir.iterdir():
        if not config_file.is_file():
            continue

        if not pl.PrivleapCommon.validate_id(str(config_file),
            pl.PrivleapValidateType.CONFIG_FILE):
            continue

        try:
            with open(str(config_file), "r", encoding = "utf-8") as f:
                action_arr: list[pl.PrivleapAction] \
                    = pl.PrivleapCommon.parse_config_file(f.read())
            PrivleapdGlobal.action_list.extend(action_arr)
        except Exception:
            print("ERROR: Failed to parse config file '"
                + str(config_file)
                + "'!",
                file=sys.stderr)
            print(traceback.format_exc())
            sys.exit(1)

def populate_state_dir() -> None:
    """
    Creates the state dir and PID file.
    """

    if not pl.PrivleapCommon.state_dir.exists():
        try:
            pl.PrivleapCommon.state_dir.mkdir(parents = True)
        except Exception:
            print("ERROR: Cannot create '"
                + str(pl.PrivleapCommon.state_dir)
                + "'!",
                file=sys.stderr)
            sys.exit(1)
    else:
        print("ERROR: '"
            + str(pl.PrivleapCommon.state_dir)
            + "' should not exist yet, but does!",
            file=sys.stderr)
        sys.exit(1)

    if not pl.PrivleapCommon.comm_dir.exists():
        try:
            pl.PrivleapCommon.comm_dir.mkdir(parents = True)
        except Exception:
            print("ERROR: Cannot create '"
                + str(pl.PrivleapCommon.comm_dir)
                + "'!",
                file=sys.stderr)
            sys.exit(1)
    else:
        print("ERROR: '"
            + str(pl.PrivleapCommon.comm_dir)
            + "' should not exist yet, but does!",
            file=sys.stderr)
        sys.exit(1)

    with open(PrivleapdGlobal.pid_file_path, "w", encoding = "utf-8") \
        as pid_file:
        pid_file.write(str(os.getpid()) + "\n")

def open_control_socket() -> None:
    """
    Opens the control socket. Privileged clients can connect to this socket to
      request that privleapd create or destroy comm sockets used for
      communicating with unprivileged users.
    """

    try:
        control_socket: pl.PrivleapSocket \
            = pl.PrivleapSocket(pl.PrivleapSocketType.CONTROL)
    except Exception:
        print("ERROR: Failed to open control socket!", file=sys.stderr)
        print(traceback.format_exc())
        sys.exit(1)

    PrivleapdGlobal.socket_list.append(control_socket)

def main_loop() -> NoReturn:
    """
    Main processing loop of privleapd. This loop will watch for and accept
      connections as needed, spawning threads to handle each individual comm
      connection. Control connections are handled in the main thread since they
      aren't a DoS risk, and running two control sessions at once could be
      dangerous.
    """

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

def main() -> NoReturn:
    """
    Main function.
    """

    ensure_running_as_root()
    verify_not_running_twice()
    cleanup_old_state_dir()
    parse_config_files()
    populate_state_dir()
    open_control_socket()
    main_loop()

if __name__ == "__main__":
    main()
