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
import socket
import re
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Tuple, cast, SupportsIndex, IO, NoReturn, Any

import sdnotify # type: ignore
# import privleap as pl
import privleap.privleap as pl

# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: This class just stores global variables, it needs no
#     public methods. Namespacing global variables in a class makes things
#     safer.
class PrivleapdGlobal:
    """
    Global variables for privleapd.
    """

    config_dir: Path = Path("/etc/privleap/conf.d")
    action_list: list[pl.PrivleapAction] = []
    persistent_user_list: list[str] = []
    allowed_user_list: list[str] = []
    socket_list: list[pl.PrivleapSocket] = []
    pid_file_path: Path = Path(pl.PrivleapCommon.state_dir, "pid")
    in_test_mode = False
    check_config_mode = False
    sdnotify_object: sdnotify.SystemdNotifier = sdnotify.SystemdNotifier()

class PrivleapdAuthStatus(Enum):
    """
    Result of checking if a user is authorized to run an action.
    """

    AUTHORIZED = 1
    USER_MISSING = 2
    UNAUTHORIZED = 3

def send_msg_safe(session: pl.PrivleapSession, msg: pl.PrivleapMsg) -> bool:
    """
    Sends a message to the client, gracefully handling the situation where the
      client has already closed the session.
    """

    if PrivleapdGlobal.in_test_mode:
        # Insert a bit of delay before sending replies, to allow the test suite
        # to win race conditions reliably.
        time.sleep(0.01)
    try:
        session.send_msg(msg)
    except Exception as e:
        logging.error("Could not send '%s'", msg.name, exc_info = e)
        return False
    return True

def handle_control_create_msg(control_session: pl.PrivleapSession,
    control_msg: pl.PrivleapControlClientCreateMsg) -> None:
    """
    Handles a CREATE control message from the client.
    """

    assert control_msg.user_name is not None
    user_name: str | None = pl.PrivleapCommon.normalize_user_id(
        control_msg.user_name)
    if user_name is None:
        logging.warning("User '%s' does not exist", control_msg.user_name)
        send_msg_safe(
            control_session, pl.PrivleapControlServerControlErrorMsg())
        return

    if user_name not in PrivleapdGlobal.allowed_user_list:
        logging.warning("User '%s' is not allowed to have a comm socket",
            control_msg.user_name)
        send_msg_safe(
            control_session, pl.PrivleapControlServerDisallowedUserMsg())
        return

    for sock in PrivleapdGlobal.socket_list:
        if sock.user_name == user_name:
            # User already has an open socket
            logging.info("Handled CREATE message for user '%s', socket already "
                "exists", user_name)
            send_msg_safe(
                control_session, pl.PrivleapControlServerExistsMsg())
            return

    try:
        comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
            pl.PrivleapSocketType.COMMUNICATION, user_name)
        PrivleapdGlobal.socket_list.append(comm_socket)
        logging.info("Handled CREATE message for user '%s', socket created",
            user_name)
        send_msg_safe(
            control_session, pl.PrivleapControlServerOkMsg())
        return
    except Exception as e:
        logging.error("Failed to create socket for user '%s'!",
            user_name, exc_info = e)
        send_msg_safe(
            control_session, pl.PrivleapControlServerControlErrorMsg())
        return

def handle_control_destroy_msg(control_session: pl.PrivleapSession,
    control_msg: pl.PrivleapControlClientDestroyMsg) -> None:
    """
    Handles a DESTROY control message from the client.
    """

    # We intentionally do not require that the user exists here, so that if a
    # user has a comm socket in existence, but also has been deleted from the
    # system, the comm socket can still be cleaned up.
    #
    # We don't have to validate the username since the
    # PrivleapControlClientDestroyMsg constructor does this for us already.
    assert control_msg.user_name is not None
    remove_sock_idx: int | None = None

    user_name: str | None = pl.PrivleapCommon.normalize_user_id(
        control_msg.user_name)
    if user_name is None:
        user_name = control_msg.user_name
    if user_name in PrivleapdGlobal.persistent_user_list:
        logging.info("Handled DESTROY message for user '%s', user is "
            "persistent, so socket not destroyed", user_name)
        send_msg_safe(
            control_session, pl.PrivleapControlServerPersistentUserMsg())
        return

    for sock_idx, sock in enumerate(PrivleapdGlobal.socket_list):
        if sock.user_name == user_name:
            socket_path: Path = Path(pl.PrivleapCommon.comm_dir,
                user_name)
            if socket_path.exists():
                try:
                    socket_path.unlink()
                except Exception as e:
                    # Probably just a TOCTOU issue, i.e. someone already
                    # removed the socket. Most likely caused by the user
                    # fiddling with things, no big deal.
                    logging.error(
                        "Handling DESTROY, failed to delete socket at '%s'!",
                        str(socket_path), exc_info = e)
            else:
                logging.warning("Handling DESTROY, no socket to delete at '%s'",
                    str(socket_path))
            remove_sock_idx = sock_idx
            break

    if remove_sock_idx is not None:
        PrivleapdGlobal.socket_list.pop(cast(SupportsIndex,
            remove_sock_idx))
        logging.info("Handled DESTROY message for user '%s', socket destroyed",
            user_name)
        send_msg_safe(
            control_session, pl.PrivleapControlServerOkMsg())
        return

    # remove_sock_idx is None.
    logging.info("Handled DESTROY message for user '%s', socket did not exist",
        user_name)
    send_msg_safe(
        control_session, pl.PrivleapControlServerNouserMsg())
    return

def handle_control_session(control_socket: pl.PrivleapSocket) -> None:
    """
    Handles control socket connections, for creating or destroying comm sockets.
    """

    try:
        control_session: pl.PrivleapSession = control_socket.get_session()
    except Exception as e:
        logging.error("Could not start session with client!", exc_info = e)
        return

    try:
        control_msg: (pl.PrivleapMsg
            | pl.PrivleapControlClientCreateMsg
            | pl.PrivleapControlClientDestroyMsg)

        try:
            control_msg = control_session.get_msg()
        except Exception as e:
            logging.error("Could not get message from client!", exc_info = e)
            return

        if isinstance(control_msg, pl.PrivleapControlClientCreateMsg):
            handle_control_create_msg(control_session, control_msg)
        elif isinstance(control_msg, pl.PrivleapControlClientDestroyMsg):
            handle_control_destroy_msg(control_session, control_msg)
        else:
            logging.critical(
                "privleapd mis-parsed a control command from the client!")
            sys.exit(2)

    finally:
        control_session.close_session()

def run_action(desired_action: pl.PrivleapAction, calling_user: str) \
    -> subprocess.Popen[bytes]:
    # pylint: disable=consider-using-with
    # Rationale:
    #   consider-using-with: Not suitable for this use case.

    """
    Runs the command defined in an action.
    """

    # There is a slight possibility that calling_user might not exist when this
    # is called, even though only users that have comm sockets will ever end up
    # with their usernames passed in here. This is because the user might have
    # been deleted after their comm socket was created. subprocess.Popen's
    # constructor does username existence checks for us already though using
    # pwd.getpwnam and grp.getgrnam though, so we don't have to re-check for
    # user existence here. Only a process with root privileges could try to win
    # any TOCTOU condition internal to subprocess.Popen by deleting the calling
    # user account at a precise time, so even if this was exploitable somehow,
    # it would only be exploitable by root, so this is not a security issue.

    # User privilege de-escalation technique inspired by
    # https://stackoverflow.com/a/6037494/19474638, using this technique since
    # it ensures the environment is also changed.

    # It's safe to assume that desired_action.{target_user,target_group}
    # represent a user and group that actually exists on the system if their
    # values are not None, since PrivleapAction's constructor checks and
    # normalizes the user and group names at creation time.

    target_user: str | None = desired_action.target_user
    target_group: str | None = desired_action.target_group

    if target_user is None and target_group is None:
        # Both user and group are unset, default to "root" for both.
        target_user = "root"
        target_group = "root"
    elif target_group is None:
        # Target user is set but group is unset, set the group to the target
        # user's default group.
        assert target_user is not None
        target_user_info = pwd.getpwnam(target_user)
        target_user_gid = target_user_info.pw_gid
        target_group = grp.getgrgid(target_user_gid).gr_name
    elif target_user is None:
        # Target group is set but user is unset, set the user to the calling
        # user. This may seem a bit weird but is consistent with sudo's
        # behavior in this situation.
        target_user = calling_user

    assert desired_action.action_command is not None
    assert target_user is not None
    assert target_group is not None
    user_info: pwd.struct_passwd = pwd.getpwnam(target_user)
    action_env: dict[str, str] = os.environ.copy()
    action_env["HOME"] = user_info.pw_dir
    action_env["LOGNAME"] = user_info.pw_name
    action_env["SHELL"] = "/usr/bin/bash"
    action_env["PWD"] = user_info.pw_dir
    action_env["USER"] = user_info.pw_name
    action_process: subprocess.Popen[bytes] = subprocess.Popen(
        ['/usr/bin/bash', '-c',
         desired_action.action_command],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE,
        stdin = subprocess.PIPE,
        user = target_user,
        group = target_group,
        env = action_env,
        cwd = user_info.pw_dir)
    assert action_process.stdin is not None
    action_process.stdin.close()
    return action_process

def get_signal_msg(comm_session: pl.PrivleapSession) \
    -> pl.PrivleapCommClientSignalMsg | None:
    """
    Gets a SIGNAL comm message from the client. Returns None if the client tries
      to send something other than a SIGNAL message.
    """

    try:
        comm_msg = comm_session.get_msg()
    except Exception as e:
        logging.error("Could not get message from client!", exc_info = e)
        return None

    if not isinstance(comm_msg, pl.PrivleapCommClientSignalMsg):
        # Illegal message, a SIGNAL needs to be the first message.
        logging.warning("Did not read SIGNAL as first message, forcibly "
            "closing connection.")
        return None

    return comm_msg

def lookup_desired_action(action_name: str) -> pl.PrivleapAction | None:
    """
    Finds the privleap action corresponding to the provided action name. Returns
      None if the action cannot be found.
    """

    for action in PrivleapdGlobal.action_list:
        if action.action_name == action_name:
            return action
    return None

def authorize_user(action: pl.PrivleapAction,
    raw_user_name: str) -> PrivleapdAuthStatus:
    """
    Ensures the user that requested an action to be run is authorized to run
      the requested action. Returns an enum value indicating if the user is
      authorized, and if not, why.
    """

    assert action.action_name is not None
    assert raw_user_name is not None

    user_name: str | None = pl.PrivleapCommon.normalize_user_id(raw_user_name)
    if user_name is None:
        # User doesn't exist? This should never happen but you never know...
        return PrivleapdAuthStatus.USER_MISSING

    if pwd.getpwnam(user_name).pw_uid == 0:
        # Root account, automatically grant access to everything
        return PrivleapdAuthStatus.AUTHORIZED

    no_auth_users: bool = False
    no_auth_groups: bool = False

    if len(action.auth_users) != 0:
        # Action exists but has restrictions on what users can run it.
        if user_name in action.auth_users:
            return PrivleapdAuthStatus.AUTHORIZED
    else:
        no_auth_users = True

    if len(action.auth_groups) != 0:
        # Action exists but has restrictions on what groups can run it.
        # We need to get the list of groups this user is a member of to
        # determine whether they are authorized or not.
        user_gid: int = pwd.getpwnam(user_name).pw_gid
        group_list: list[str] = [grp.getgrgid(gid).gr_name \
            for gid in os.getgrouplist(user_name, user_gid)]
        for group in group_list:
            if group in action.auth_groups:
                return PrivleapdAuthStatus.AUTHORIZED
    else:
        no_auth_groups = True

    if no_auth_users and no_auth_groups:
        # Action has no restrictions, grant access
        return PrivleapdAuthStatus.AUTHORIZED

    # Action had restrictions that could not be met, deny access
    return PrivleapdAuthStatus.UNAUTHORIZED

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
                        pl.PrivleapCommServerResultStdoutMsg(stdio_buf)):
                        return
            if action_process.stderr in ready_streams[0]:
                stdio_buf = action_process.stderr.read(1024)
                if stdio_buf == b"":
                    stderr_done = True
                else:
                    if not send_msg_safe(comm_session,
                        pl.PrivleapCommServerResultStderrMsg(stdio_buf)):
                        return

        action_process.wait()

    finally:
        action_process.stdout.close()
        action_process.stderr.close()
        action_process.terminate()
        action_process.wait()
        # Process is done, send the exit code and clean up
        logging.info("Action '%s' completed", action_name)

    send_msg_safe(comm_session, pl.PrivleapCommServerResultExitcodeMsg(
        action_process.returncode))

def auth_signal_request(comm_msg: pl.PrivleapCommClientSignalMsg,
    comm_session: pl.PrivleapSession) -> pl.PrivleapAction | None:
    """
    Finds the requested action, and ensures that the calling user has the
      permissions to run it. Returns the desired action if auth succeeds.
      Returns None, sends an UNAUTHORIZED message to the user, and logs the
      reason for authentication failure if auth fails or the action does not
      exist.
    """

    # The auth code attempts to NOT allow a client to tell the difference
    # between an action that doesn't exist, and one that does exist but that
    # they aren't allowed to execute. If authentication fails or the action
    # doesn't exist, we make sure the server takes as close to 3 seconds to
    # reply as possible. If we wanted to cloak this list even better, we
    # could busy-wait rather than sleeping to avoid processor load acting
    # as a side-channel, but that would potentially allow DoS attacks which
    # are probably a bigger threat.
    auth_start_time: float = time.monotonic()
    desired_action: pl.PrivleapAction | None = lookup_desired_action(
        comm_msg.signal_name)
    auth_result: PrivleapdAuthStatus | None = None
    if desired_action is not None:
        assert comm_session.user_name is not None
        auth_result = authorize_user(desired_action, comm_session.user_name)

    if auth_result != PrivleapdAuthStatus.AUTHORIZED:
        if auth_result is None:
            logging.warning("Could not find action '%s'",
                comm_msg.signal_name)
        else:
            assert desired_action is not None
            assert desired_action.action_name is not None
            if auth_result == PrivleapdAuthStatus.USER_MISSING:
                logging.warning(
                    "User '%s' does not exist, cannot run action '%s'",
                    comm_session.user_name, desired_action.action_name)
            elif auth_result == PrivleapdAuthStatus.UNAUTHORIZED:
                logging.warning(
                    "User '%s' is not authorized to run action '%s'",
                    comm_session.user_name, desired_action.action_name)
        auth_end_time: float = auth_start_time + 3
        auth_fail_sleep_time: float = auth_end_time - auth_start_time
        if auth_fail_sleep_time > 0:
            time.sleep(auth_fail_sleep_time)
        send_msg_safe(comm_session, pl.PrivleapCommServerUnauthorizedMsg())
        return None

    assert desired_action is not None
    return desired_action

def handle_comm_session(comm_socket: pl.PrivleapSocket) -> None:
    """
    Handles comm socket connections, for running actions.
    """

    try:
        comm_session: pl.PrivleapSession = comm_socket.get_session()
    except Exception as e:
        logging.error("Could not start session with client!", exc_info = e)
        return

    assert comm_session.user_name is not None

    try:
        comm_msg: pl.PrivleapCommClientSignalMsg | None \
            = get_signal_msg(comm_session)
        if comm_msg is None:
            return

        desired_action: pl.PrivleapAction | None = auth_signal_request(comm_msg,
            comm_session)

        if desired_action is None:
            return
        assert desired_action.action_name is not None

        try:
            action_process: subprocess.Popen[bytes] = run_action(desired_action,
                comm_session.user_name)
        except Exception as e:
            logging.error("Action '%s' authorized, but trigger failed!",
                desired_action.action_name, exc_info = e)
            send_msg_safe(comm_session, pl.PrivleapCommServerTriggerErrorMsg())
            return

        logging.info("Triggered action '%s'", desired_action.action_name)

        # We don't bail out if this message send fails, since we still need to
        # monitor and manage the child process, which is part of what
        # send_action_results() does.
        send_msg_safe(comm_session, pl.PrivleapCommServerTriggerMsg())
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
        logging.critical("privleapd must run as root!")
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
            # If no exception, the old privleapd process is still running.
            logging.critical("Cannot run two privleapd processes at the same "
                "time!")
            sys.exit(1)
        except OSError:
            return
        except Exception as e:
            logging.critical("Could not check for simultaneously running "
                "privleapd process!", exc_info = e)
            sys.exit(1)

def cleanup_old_state_dir() -> None:
    """
    Cleans up the old state directory left behind by a previous privleapd
      instance.
    """

    # This probably won't run anywhere but Linux, but just in case, make sure
    # we aren't opening a security hole
    if not shutil.rmtree.avoids_symlink_attacks:
        logging.critical("This platform does not allow recursive deletion of a "
            "directory without a symlink attack vuln!")
        sys.exit(1)
    # Cleanup any sockets left behind by an old privleapd process
    if pl.PrivleapCommon.state_dir.exists():
        try:
            shutil.rmtree(pl.PrivleapCommon.state_dir)
        except Exception as e:
            logging.critical("Could not delete '%s'!",
                str(pl.PrivleapCommon.state_dir), exc_info = e)
            sys.exit(1)

def append_if_not_in(item: Any, item_list: list[Any]) -> None:
    """
    Append an item to a list if the item is not already in the list.
    """

    if item not in item_list:
        item_list.append(item)

def parse_config_files() -> None:
    """
    Parses all config files under /etc/privleap/conf.d.
    """

    config_file_list: list[Path] = []
    for config_file in PrivleapdGlobal.config_dir.iterdir():
        if not config_file.is_file():
            continue
        config_file_list.append(config_file)
    config_file_list.sort()

    for config_file in config_file_list:
        if not config_file.is_file():
            continue

        if not pl.PrivleapCommon.validate_id(str(config_file),
            pl.PrivleapValidateType.CONFIG_FILE):
            continue

        try:
            action_arr: list[pl.PrivleapAction]
            persistent_user_arr: list[str]
            allowed_user_arr: list[str]
            action_arr, persistent_user_arr, allowed_user_arr \
                = pl.PrivleapCommon.parse_config_file(config_file)
            for action_item in action_arr:
                for existing_action_item in PrivleapdGlobal.action_list:
                    if action_item.action_name \
                        == existing_action_item.action_name:
                        raise ValueError("Duplicate action "
                            f"'{action_item.action_name}' found!")
                PrivleapdGlobal.action_list.append(action_item)
            for persistent_user_item in persistent_user_arr:
                # Note, parse_config_file() normalizes the usernames of
                # persistent users for us.
                append_if_not_in(persistent_user_item,
                    PrivleapdGlobal.persistent_user_list)
                # Persistent users are automatically allowed users too.
                append_if_not_in(persistent_user_item,
                    PrivleapdGlobal.allowed_user_list)
                # It isn't an error for duplicate persistent users to be
                # defined, we just skip over the duplicates.
            for allowed_user_item in allowed_user_arr:
                # Note, parse_config_file() normalizes the usernames of
                # allowed users for us.
                append_if_not_in(allowed_user_item,
                    PrivleapdGlobal.allowed_user_list)
                # It isn't an error for duplicate allowed users to be
                # defined, we just skip over the duplicates.
        except Exception as e:
            logging.critical("Failed to load config file '%s'!",
                str(config_file), exc_info = e)
            if PrivleapdGlobal.check_config_mode:
                # pylint: disable=raise-missing-from
                # Rationale:
                #   raise-missing-from: We're only using an exception here to
                #     notify the config check mechanism that config parsing
                #     failed. We do not need to re-raise the earlier exception,
                #     and we already print out the earlier exception's traceback
                #     using logging.critical().
                raise ValueError("Config check failed!")
            sys.exit(1)

def populate_state_dir() -> None:
    """
    Creates the state dir and PID file.
    """

    if not pl.PrivleapCommon.state_dir.exists():
        try:
            pl.PrivleapCommon.state_dir.mkdir(parents = True)
        except Exception as e:
            logging.critical("Cannot create '%s'!",
                str(pl.PrivleapCommon.state_dir), exc_info = e)
            sys.exit(1)
    else:
        logging.critical("Directory '%s' should not exist yet, but does!",
            str(pl.PrivleapCommon.state_dir))
        sys.exit(1)

    if not pl.PrivleapCommon.comm_dir.exists():
        try:
            pl.PrivleapCommon.comm_dir.mkdir(parents = True)
        except Exception as e:
            logging.critical("Cannot create '%s'!",
                str(pl.PrivleapCommon.comm_dir), exc_info = e)
            sys.exit(1)
    else:
        logging.critical("Directory '%s' should not exist yet, but does!",
            str(pl.PrivleapCommon.comm_dir))
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
    except Exception as e:
        logging.critical("Failed to open control socket!", exc_info = e)
        sys.exit(1)

    PrivleapdGlobal.socket_list.append(control_socket)

def open_persistent_comm_sockets() -> None:
    """
    Opens comm sockets for persistent users. privleapd will treat these sockets
      like normal sockets, but opens them without needing a privileged client to
      request their creation, and does NOT allow a privileged client to destroy
      them.
    """

    for user_name in PrivleapdGlobal.persistent_user_list:
        try:
            comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
                pl.PrivleapSocketType.COMMUNICATION, user_name)
            PrivleapdGlobal.socket_list.append(comm_socket)
            # We intentionally don't log the creation of persistent user sockets
            # since for one, doing so would needlessly clutter the system logs
            # (the list of persistent users can be determined by just looking
            # at privleap's config), and for two, privleap doesn't output log
            # information during early startup unless something is wrong. The
            # test suite depends on this behavior, so it's not something we want
            # to break unless necessary.
        except Exception as e:
            logging.error("Failed to create persistent socket for user '%s'!",
                user_name, exc_info = e)
            return

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
            list[IO[bytes]]] = select.select(
                [sock_obj.backend_socket \
                    for sock_obj in PrivleapdGlobal.socket_list],
                [],
                [],
                5
            )
        PrivleapdGlobal.sdnotify_object.notify("WATCHDOG=1")
        for ready_socket in ready_socket_list[0]:
            ready_sock_obj: pl.PrivleapSocket | None = None
            for sock_obj in PrivleapdGlobal.socket_list:
                if sock_obj.backend_socket == cast(socket.socket, ready_socket):
                    ready_sock_obj = sock_obj
                    break
            if ready_sock_obj is None:
                logging.critical("privleapd lost track of a socket!")
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

    logging.basicConfig(format = "%(funcName)s: %(levelname)s: %(message)s",
        level = logging.INFO)
    for idx, arg in enumerate(sys.argv):
        if idx == 0:
            continue
        if arg == "--test":
            PrivleapdGlobal.in_test_mode = True
        elif arg in ("-C", "--check-config"):
            PrivleapdGlobal.check_config_mode = True
        else:
            logging.critical("Unrecognized argument '%s'!", arg)
            sys.exit(1)

    if PrivleapdGlobal.check_config_mode:
        try:
            parse_config_files()
        except ValueError:
            logging.critical("privleap config is bad.")
            sys.exit(1)
        logging.info("privleap config is OK.")
        sys.exit(0)

    ensure_running_as_root()
    verify_not_running_twice()
    cleanup_old_state_dir()
    parse_config_files()
    populate_state_dir()
    open_control_socket()
    open_persistent_comm_sockets()
    PrivleapdGlobal.sdnotify_object.notify("READY=1")
    PrivleapdGlobal.sdnotify_object.notify("STATUS=Fully started")
    main_loop()

if __name__ == "__main__":
    main()
