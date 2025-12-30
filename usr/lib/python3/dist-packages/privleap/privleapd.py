#!/usr/bin/python3 -su

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, too-many-lines
# Rationale:
#   broad-exception-caught: except blocks are intended to catch all possible
#     exceptions in each instance to prevent server crashes.
#   too-many-lines: Splitting this up would make it less readable at this point.

"""privleapd.py - privleap background process."""

import sys
import shutil
import select
from threading import Thread
import os
import pwd
import grp
import subprocess
import re
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Tuple, cast, SupportsIndex, NoReturn, Any

import sdnotify  # type: ignore

from .privleap import (
    ConfigData,
    PrivleapAction,
    PrivleapCommClientAccessCheckMsg,
    PrivleapCommClientSignalMsg,
    PrivleapCommClientTerminateMsg,
    PrivleapCommon,
    PrivleapCommServerAuthorizedMsg,
    PrivleapCommServerResultExitcodeMsg,
    PrivleapCommServerResultStderrMsg,
    PrivleapCommServerResultStdoutMsg,
    PrivleapCommServerTriggerErrorMsg,
    PrivleapCommServerTriggerMsg,
    PrivleapCommServerUnauthorizedMsg,
    PrivleapControlClientCreateMsg,
    PrivleapControlClientDestroyMsg,
    PrivleapControlClientReloadMsg,
    PrivleapControlServerControlErrorMsg,
    PrivleapControlServerDisallowedUserMsg,
    PrivleapControlServerExistsMsg,
    PrivleapControlServerExpectedDisallowedUserMsg,
    PrivleapControlServerNouserMsg,
    PrivleapControlServerOkMsg,
    PrivleapControlServerPersistentUserMsg,
    PrivleapMsg,
    PrivleapSession,
    PrivleapSocket,
    PrivleapSocketType,
    PrivleapValidateType,
)


# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: This class just stores global variables, it needs no
#     public methods. Namespacing global variables in a class makes things
#     safer.
class PrivleapdGlobal:
    """
    Global variables for privleapd.
    """

    config_dir_list: list[Path] = [
        Path("/etc/privleap/conf.d"),
        Path("/usr/local/etc/privleap/conf.d"),
    ]
    action_list: list[PrivleapAction] = []
    persistent_user_list: list[str] = []
    allowed_user_list: list[str] = []
    allowed_group_list: list[str] = []
    expected_disallowed_user_list: list[str] = []
    socket_list: list[PrivleapSocket] = []
    pid_file_path: Path = Path(PrivleapCommon.state_dir, "pid")
    test_mode = False
    check_config_mode = False
    debug_mode = False
    sdnotify_object: sdnotify.SystemdNotifier = sdnotify.SystemdNotifier()
    old_umask: int = 0


class PrivleapdAuthStatus(Enum):
    """
    Result of checking if a user is authorized to run an action.
    """

    AUTHORIZED = 1
    USER_MISSING = 2
    UNAUTHORIZED = 3


class PrivleapdCommDestroyResult(Enum):
    """
    The result of attempting to destroy a comm socket.
    """

    SUCCESS = 0
    NO_USER = 1
    PERSISTENT_USER = 2


def send_msg_safe(session: PrivleapSession, msg: PrivleapMsg) -> bool:
    """
    Sends a message to the client, gracefully handling the situation where the
      client has already closed the session.
    """

    if PrivleapdGlobal.test_mode:
        # Insert a bit of delay before sending replies, to allow the test suite
        # to win race conditions reliably.
        time.sleep(0.01)
    try:
        session.send_msg(msg)
    except Exception as e:
        logging.error("Could not send '%s'", msg.name, exc_info=e)
        return False
    return True


def user_in_allowed_group(user_name: str) -> bool:
    """
    Returns True if user_name currently belongs to an allowed group. Looks up
      user and group data from scratch on each call, so that if user group
      membership changes between calls, privleapd notices.
    """

    try:
        user_info: pwd.struct_passwd = pwd.getpwnam(user_name)
    except KeyError:
        return False
    except Exception as e:
        logging.error(
            "Unexpected error looking up account '%s'",
            user_name,
            exc_info=e,
        )
        return False

    for group_name in PrivleapdGlobal.allowed_group_list:
        try:
            group_info: grp.struct_group = grp.getgrnam(group_name)
        except KeyError:
            logging.warning(
                "Configured allowed group '%s' no longer exists", group_name
            )
            continue
        except Exception as e:
            logging.error(
                "Unexpected error looking up group '%s'",
                group_name,
                exc_info=e,
            )
            continue
        if (
            user_info.pw_gid == group_info.gr_gid
            or user_name in group_info.gr_mem
        ):
            return True

    return False


def is_user_allowed(user_name: str) -> bool:
    """
    Returns True if user_name is present in the allowed user list or is a
      member of a group present in the allowed group list.
    """

    if user_name in PrivleapdGlobal.allowed_user_list:
        return True
    return user_in_allowed_group(user_name)


def prune_disallowed_comm_sockets() -> None:
    """
    Remove comm sockets for users who are no longer allowed to connect to
    privleap.
    """

    user_names_to_kick: list[str] = []

    for sock in PrivleapdGlobal.socket_list:
        if sock.socket_type != PrivleapSocketType.COMMUNICATION:
            continue
        assert sock.user_name is not None
        if is_user_allowed(sock.user_name):
            continue
        user_names_to_kick.append(sock.user_name)

    for user_name in user_names_to_kick:
        logging.info(
            "Destroying comm socket for no-longer-allowed account '%s'",
            user_name,
        )
        _, _ = destroy_comm_socket(user_name)


def handle_control_create_msg(
    control_session: PrivleapSession,
    control_msg: PrivleapControlClientCreateMsg,
) -> None:
    """
    Handles a CREATE control message from the client.
    """

    assert control_msg.user_name is not None
    user_name: str | None = PrivleapCommon.normalize_user_id(
        control_msg.user_name
    )
    if user_name is None:
        logging.warning("Account '%s' does not exist", control_msg.user_name)
        send_msg_safe(control_session, PrivleapControlServerControlErrorMsg())
        return

    if user_name in PrivleapdGlobal.expected_disallowed_user_list:
        logging.info(
            "Expected disallowed account '%s' requested a comm socket, "
            "request denied",
            user_name,
        )
        send_msg_safe(
            control_session, PrivleapControlServerExpectedDisallowedUserMsg()
        )
        return

    if not is_user_allowed(user_name):
        logging.warning(
            "Account '%s' is not allowed to have a comm socket", user_name
        )
        send_msg_safe(control_session, PrivleapControlServerDisallowedUserMsg())
        return

    for sock in PrivleapdGlobal.socket_list:
        if sock.user_name == user_name:
            # User already has an open socket
            logging.info(
                "Handled CREATE message for account '%s', socket already "
                "exists",
                user_name,
            )
            send_msg_safe(control_session, PrivleapControlServerExistsMsg())
            return

    try:
        comm_socket: PrivleapSocket = PrivleapSocket(
            PrivleapSocketType.COMMUNICATION, user_name
        )
        PrivleapdGlobal.socket_list.append(comm_socket)
        logging.info(
            "Handled CREATE message for account '%s', socket created", user_name
        )
        send_msg_safe(control_session, PrivleapControlServerOkMsg())
        return
    except Exception as e:
        logging.error(
            "Failed to create socket for account '%s'!", user_name, exc_info=e
        )
        send_msg_safe(control_session, PrivleapControlServerControlErrorMsg())
        return


def destroy_comm_socket(
    user_name: str,
) -> tuple[str, PrivleapdCommDestroyResult]:
    """
    Destroys the comm socket for the specified username. Returns the real user
      name that the function attempted to destroy a socket for, and the result
      of the destroy operation.
    """

    remove_sock_idx: int | None = None

    # We intentionally do not require that the user exists here, so that if a
    # user has a comm socket in existence, but also has been deleted from the
    # system, the comm socket can still be cleaned up.
    real_user_name: str | None = PrivleapCommon.normalize_user_id(user_name)
    if real_user_name is None:
        real_user_name = user_name

    if real_user_name in PrivleapdGlobal.persistent_user_list:
        logging.info(
            "Refusing to destroy comm socket for persistent account '%s'",
            real_user_name,
        )
        return real_user_name, PrivleapdCommDestroyResult.PERSISTENT_USER

    for sock_idx, sock in enumerate(PrivleapdGlobal.socket_list):
        if sock.user_name == real_user_name:
            socket_path: Path = Path(PrivleapCommon.comm_dir, real_user_name)
            if socket_path.exists():
                try:
                    socket_path.unlink()
                except Exception as e:
                    ## Probably just a TOCTOU issue, i.e. someone already
                    ## removed the socket. Most likely caused by the user
                    ## fiddling with things, no big deal.
                    logging.error(
                        "Destroying comm socket for account '%s', failed to "
                        "delete UNIX socket at '%s'",
                        real_user_name,
                        str(socket_path),
                        exc_info=e,
                    )
            else:
                logging.warning(
                    "Destroying comm socket for account '%s', no UNIX socket "
                    "to delete at '%s'",
                    real_user_name,
                    str(socket_path),
                )
            remove_sock_idx = sock_idx
            break

    if remove_sock_idx is not None:
        PrivleapdGlobal.socket_list.pop(cast(SupportsIndex, remove_sock_idx))
        logging.info(
            "Successfully destroyed comm socket for account '%s'",
            real_user_name,
        )
        return real_user_name, PrivleapdCommDestroyResult.SUCCESS

    logging.info(
        "Could not destroy comm socket for account '%s', account has no comm "
        "socket open",
        real_user_name,
    )
    return real_user_name, PrivleapdCommDestroyResult.NO_USER


def handle_control_destroy_msg(
    control_session: PrivleapSession,
    control_msg: PrivleapControlClientDestroyMsg,
) -> None:
    """
    Handles a DESTROY control message from the client.
    """

    assert control_msg.user_name is not None

    real_user_name: str
    result_val: PrivleapdCommDestroyResult

    ## We don't have to validate the username since the
    ## PrivleapControlClientDestroyMsg constructor does this for us already.
    real_user_name, result_val = destroy_comm_socket(control_msg.user_name)
    match result_val:
        case PrivleapdCommDestroyResult.SUCCESS:
            logging.info(
                "Handled DESTROY message for account '%s', socket destroyed",
                real_user_name,
            )
            send_msg_safe(control_session, PrivleapControlServerOkMsg())
        case PrivleapdCommDestroyResult.NO_USER:
            logging.info(
                "Handled DESTROY message for account '%s', socket did not "
                "exist",
                real_user_name,
            )
            send_msg_safe(control_session, PrivleapControlServerNouserMsg())
        case PrivleapdCommDestroyResult.PERSISTENT_USER:
            logging.info(
                "Handled DESTROY message for account '%s', account is "
                "persistent, so socket not destroyed",
                real_user_name,
            )
            send_msg_safe(
                control_session, PrivleapControlServerPersistentUserMsg()
            )


def handle_control_reload_msg(control_session: PrivleapSession) -> None:
    """
    Handles a RELOAD message from the client.
    """

    if parse_config_files():
        logging.info("Handled RELOAD message, configuration reloaded")
        prune_disallowed_comm_sockets()
        send_msg_safe(control_session, PrivleapControlServerOkMsg())
    else:
        logging.warning("Handled RELOAD message, configuration was invalid!")
        send_msg_safe(control_session, PrivleapControlServerControlErrorMsg())


def handle_control_session(control_socket: PrivleapSocket) -> None:
    """
    Handles control socket connections, for creating or destroying comm sockets.
    """

    try:
        control_session: PrivleapSession = control_socket.get_session()
    except Exception as e:
        logging.error(
            "Could not start control session with client!", exc_info=e
        )
        return

    try:
        control_msg: (
            PrivleapMsg
            | PrivleapControlClientCreateMsg
            | PrivleapControlClientDestroyMsg
        )

        try:
            control_msg = control_session.get_msg()
        except Exception as e:
            logging.error(
                "Could not get message from control client!", exc_info=e
            )
            return

        if isinstance(control_msg, PrivleapControlClientCreateMsg):
            handle_control_create_msg(control_session, control_msg)
        elif isinstance(control_msg, PrivleapControlClientDestroyMsg):
            handle_control_destroy_msg(control_session, control_msg)
        elif isinstance(control_msg, PrivleapControlClientReloadMsg):
            handle_control_reload_msg(control_session)
        else:
            logging.critical(
                "privleapd mis-parsed a control command from the client!"
            )
            sys.exit(2)

    finally:
        control_session.close_session()


def run_action(
    desired_action: PrivleapAction, calling_user: str
) -> subprocess.Popen[bytes]:
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
        target_user_info: pwd.struct_passwd = pwd.getpwnam(target_user)
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

    action_process: subprocess.Popen[bytes] = subprocess.Popen(
        [
            "/usr/libexec/privleap/shim.py",
            calling_user,
            target_user,
            target_group,
            str(PrivleapdGlobal.old_umask),
            "/usr/bin/bash",
            "-c",
            "--",
            desired_action.action_command,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
    )
    assert action_process.stdin is not None
    assert action_process.stdout is not None
    assert action_process.stderr is not None
    os.set_blocking(action_process.stdout.fileno(), False)
    os.set_blocking(action_process.stderr.fileno(), False)
    action_process.stdin.close()
    return action_process


def get_client_initial_msg(
    comm_session: PrivleapSession,
) -> PrivleapCommClientSignalMsg | PrivleapCommClientAccessCheckMsg | None:
    """
    Gets a SIGNAL or ACCESS_CHECK comm message from the client. Returns
      None if the client tries to send something other than a SIGNAL or
      ACCESS_CHECK message.
    """

    try:
        comm_msg: PrivleapMsg = comm_session.get_msg()
    except Exception as e:
        logging.error(
            "Could not get message from client run by account '%s'!",
            comm_session.user_name,
            exc_info=e,
        )
        return None

    if not (
        isinstance(
            comm_msg,
            (
                PrivleapCommClientSignalMsg,
                PrivleapCommClientAccessCheckMsg,
            ),
        )
    ):
        # Illegal message, a SIGNAL or ACCESS_CHECK needs to be the first
        # message.
        logging.warning(
            "Did not read SIGNAL or ACCESS_CHECK as first message from "
            "client run by account '%s', forcibly closing connection.",
            comm_session.user_name,
        )
        return None

    return comm_msg


def lookup_desired_action(action_name: str) -> PrivleapAction | None:
    """
    Finds the privleap action corresponding to the provided action name. Returns
      None if the action cannot be found.
    """

    for action in PrivleapdGlobal.action_list:
        if action.action_name == action_name:
            return action
    return None


def authorize_user(
    action: PrivleapAction, raw_user_name: str
) -> PrivleapdAuthStatus:
    """
    Ensures the user that requested an action to be run is authorized to run
      the requested action. Returns an enum value indicating if the user is
      authorized, and if not, why.
    """

    assert action.action_name is not None
    assert raw_user_name is not None

    user_name: str | None = PrivleapCommon.normalize_user_id(raw_user_name)
    if user_name is None:
        # User doesn't exist? This should never happen, but you never know...
        return PrivleapdAuthStatus.USER_MISSING

    if pwd.getpwnam(user_name).pw_uid == 0:
        # Root account, automatically grant access to everything
        return PrivleapdAuthStatus.AUTHORIZED

    if not action.auth_restricted:
        # Action has no restrictions, grant access
        return PrivleapdAuthStatus.AUTHORIZED

    if len(action.auth_users) != 0:
        # Action exists but has restrictions on what users can run it.
        if user_name in action.auth_users:
            return PrivleapdAuthStatus.AUTHORIZED

    if len(action.auth_groups) != 0:
        # Action exists but has restrictions on what groups can run it.
        # We need to get the list of groups this user is a member of to
        # determine whether they are authorized or not.
        user_gid: int = pwd.getpwnam(user_name).pw_gid
        group_list: list[str] = [
            grp.getgrgid(gid).gr_name
            for gid in os.getgrouplist(user_name, user_gid)
        ]
        for group in group_list:
            if group in action.auth_groups:
                return PrivleapdAuthStatus.AUTHORIZED

    # Action had restrictions that could not be met, deny access
    return PrivleapdAuthStatus.UNAUTHORIZED


def check_action_terminate(
    comm_session: PrivleapSession, action_name: str
) -> bool:
    """
    Checks for a TERMINATE message from the client.
    """

    assert comm_session.backend_socket is not None
    ready_streams: Tuple[list[int], list[int], list[int]] = select.select(
        [comm_session.backend_socket.fileno()], [], [], 0
    )
    if comm_session.backend_socket.fileno() in ready_streams[0]:
        try:
            comm_msg: PrivleapMsg = comm_session.get_msg()
        except Exception as e:
            logging.error(
                "Could not get message from client run by account '%s'!",
                comm_session.user_name,
                exc_info=e,
            )
            return True
        if isinstance(comm_msg, PrivleapCommClientTerminateMsg):
            logging.info(
                "Action '%s' prematurely terminated by account '%s'",
                action_name,
                comm_session.user_name,
            )
            return True
        logging.error(
            "Received invalid message type '%s' from client run by account '%s'!",
            type(comm_msg).__name__,
            comm_session.user_name,
        )
        return True

    return False


def send_action_results(
    comm_session: PrivleapSession,
    action_name: str,
    action_process: subprocess.Popen[bytes],
) -> None:
    """
    Streams the stdout and stderr of the running action to the client, and sends
      the exitcode once the action is finished running.
    """

    assert action_process.stdout is not None
    assert action_process.stderr is not None
    assert comm_session.backend_socket is not None

    try:
        stdout_done: bool = False
        stderr_done: bool = False

        while not stdout_done or not stderr_done:
            select.select(
                [
                    action_process.stdout.fileno(),
                    action_process.stderr.fileno(),
                    comm_session.backend_socket.fileno(),
                ],
                [],
                [],
            )

            while True:
                if check_action_terminate(comm_session, action_name):
                    return

                stdout_buf: bytes | None = action_process.stdout.read(1024)
                stderr_buf: bytes | None = action_process.stderr.read(1024)

                if stdout_buf == b"":
                    stdout_done = True
                elif stdout_buf is not None:
                    if not send_msg_safe(
                        comm_session,
                        PrivleapCommServerResultStdoutMsg(stdout_buf),
                    ):
                        return

                if stderr_buf == b"":
                    stderr_done = True
                elif stderr_buf is not None:
                    if not send_msg_safe(
                        comm_session,
                        PrivleapCommServerResultStderrMsg(stderr_buf),
                    ):
                        return

                if (stdout_buf is None or stdout_done) and (
                    stderr_buf is None or stderr_done
                ):
                    break

        action_process.wait()

    finally:
        action_process.stdout.close()
        action_process.stderr.close()
        action_process.terminate()
        action_process.wait()
        # Process is done, send the exit code and clean up
        logging.info(
            "Action '%s' requested by account '%s' completed",
            action_name,
            comm_session.user_name,
        )

    send_msg_safe(
        comm_session,
        PrivleapCommServerResultExitcodeMsg(action_process.returncode),
    )


def auth_signal_request(
    comm_msg: PrivleapMsg, comm_session: PrivleapSession
) -> PrivleapAction | None:
    """
    Finds the requested action, and ensures that the calling user has the
      permissions to run it. Returns the desired action if auth succeeds.
      Returns None, sends an UNAUTHORIZED message to the user, and logs the
      reason for authentication failure if auth fails or the action does not
      exist.
    """

    auth_type: str
    if isinstance(comm_msg, PrivleapCommClientSignalMsg):
        auth_type = "Action run request"
    elif isinstance(comm_msg, PrivleapCommClientAccessCheckMsg):
        auth_type = "Access check"
    else:
        logging.critical("Invalid message type provided!")
        sys.exit(1)

    assert isinstance(
        comm_msg,
        (PrivleapCommClientSignalMsg, PrivleapCommClientAccessCheckMsg),
    )
    # The auth code attempts to NOT allow a client to tell the difference
    # between an action that doesn't exist, and one that does exist but that
    # they aren't allowed to execute. If authentication fails or the action
    # doesn't exist, we make sure the server takes as close to 3 seconds to
    # reply as possible. If we wanted to cloak this list even better, we
    # could busy-wait rather than sleeping to avoid processor load acting
    # as a side-channel, but that would potentially allow DoS attacks which
    # are probably a bigger threat.
    auth_start_time: float = time.monotonic()
    desired_action: PrivleapAction | None = lookup_desired_action(
        comm_msg.signal_name
    )
    auth_result: PrivleapdAuthStatus | None = None
    if desired_action is not None:
        assert comm_session.user_name is not None
        auth_result = authorize_user(desired_action, comm_session.user_name)

    if auth_result != PrivleapdAuthStatus.AUTHORIZED:
        if auth_result is None:
            logging.warning(
                "%s: Could not find action '%s' requested by account '%s'",
                auth_type,
                comm_msg.signal_name,
                comm_session.user_name,
            )
        else:
            assert desired_action is not None
            assert desired_action.action_name is not None
            if auth_result == PrivleapdAuthStatus.USER_MISSING:
                logging.warning(
                    "%s: Account '%s' does not exist, cannot run action '%s'",
                    auth_type,
                    comm_session.user_name,
                    desired_action.action_name,
                )
            elif auth_result == PrivleapdAuthStatus.UNAUTHORIZED:
                logging.warning(
                    "%s: Account '%s' is not authorized to run action '%s'",
                    auth_type,
                    comm_session.user_name,
                    desired_action.action_name,
                )
        auth_end_time: float = auth_start_time + 3
        auth_fail_sleep_time: float = auth_end_time - auth_start_time
        if auth_fail_sleep_time > 0:
            time.sleep(auth_fail_sleep_time)
        send_msg_safe(comm_session, PrivleapCommServerUnauthorizedMsg())
        return None

    assert desired_action is not None
    logging.info(
        "%s: Account '%s' is authorized to run action '%s'",
        auth_type,
        comm_session.user_name,
        desired_action.action_name,
    )
    return desired_action


def handle_signal_message(
    desired_action: PrivleapAction, comm_session: PrivleapSession
) -> None:
    """
    Handles a SIGNAL message from the client.
    """

    assert comm_session.user_name is not None
    try:
        action_process: subprocess.Popen[bytes]
        action_process = run_action(desired_action, comm_session.user_name)
    except Exception as e:
        logging.error(
            "Action '%s' authorized for account '%s', but trigger failed!",
            desired_action.action_name,
            comm_session.user_name,
            exc_info=e,
        )
        send_msg_safe(comm_session, PrivleapCommServerTriggerErrorMsg())
        return

    logging.info(
        "Triggered action '%s' for account '%s'",
        desired_action.action_name,
        comm_session.user_name,
    )

    # We don't bail out if this message send fails, since we still need to
    # monitor and manage the child process, which is part of what
    # send_action_results() does.
    send_msg_safe(comm_session, PrivleapCommServerTriggerMsg())
    assert desired_action.action_name is not None
    send_action_results(
        comm_session, desired_action.action_name, action_process
    )


def handle_comm_session(comm_socket: PrivleapSocket) -> None:
    """
    Handles comm socket connections, for running actions.
    """

    try:
        comm_session: PrivleapSession = comm_socket.get_session()
    except Exception as e:
        logging.error(
            "Could not start comm session with client run by account '%s'!",
            comm_socket.user_name,
            exc_info=e,
        )
        return

    assert comm_session.user_name is not None
    if not is_user_allowed(comm_session.user_name):
        logging.warning(
            "Ending session and destroying comm socket for no-longer-allowed "
            "account '%s'",
            comm_session.user_name,
        )
        comm_session.close_session()
        _, _ = destroy_comm_socket(comm_session.user_name)
        return

    try:
        comm_msg: (
            PrivleapCommClientSignalMsg
            | PrivleapCommClientAccessCheckMsg
            | None
        ) = get_client_initial_msg(comm_session)
        if comm_msg is None:
            return

        desired_action: PrivleapAction | None = auth_signal_request(
            comm_msg, comm_session
        )

        if desired_action is None:
            return

        if isinstance(comm_msg, PrivleapCommClientSignalMsg):
            handle_signal_message(desired_action, comm_session)
        elif isinstance(comm_msg, PrivleapCommClientAccessCheckMsg):
            # We already authorized the request above, so we can simply tell the
            # client about that now.
            send_msg_safe(comm_session, PrivleapCommServerAuthorizedMsg())

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

    with open(PrivleapdGlobal.pid_file_path, "r", encoding="utf-8") as pid_file:
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
            logging.critical(
                "Cannot run two privleapd processes at the same time!"
            )
            sys.exit(1)
        except OSError:
            return
        except Exception as e:
            logging.critical(
                "Could not check for simultaneously running privleapd "
                "process!",
                exc_info=e,
            )
            sys.exit(1)


def cleanup_old_state_dir() -> None:
    """
    Cleans up the old state directory left behind by a previous privleapd
      instance.
    """

    # This probably won't run anywhere but Linux, but just in case, make sure
    # we aren't opening a security hole
    if not shutil.rmtree.avoids_symlink_attacks:
        logging.critical(
            "This platform does not allow recursive deletion of a directory "
            "without a symlink attack vuln!"
        )
        sys.exit(1)
    # Cleanup any sockets left behind by an old privleapd process
    if PrivleapCommon.state_dir.exists():
        try:
            shutil.rmtree(PrivleapCommon.state_dir)
        except Exception as e:
            logging.critical(
                "Could not delete '%s'!",
                str(PrivleapCommon.state_dir),
                exc_info=e,
            )
            sys.exit(1)


def append_if_not_in(item: Any, item_list: list[Any]) -> None:
    """
    Append an item to a list if the item is not already in the list.
    """

    if item not in item_list:
        item_list.append(item)


def extend_action_list(
    action_arr: list[PrivleapAction], target_arr: list[PrivleapAction]
) -> str | None:
    """
    Extend PrivleapdGlobal.action_list with the contents of action_arr. If a
      duplicate action is found, stop early and return the name of the
      duplicate, otherwise return None.
    """
    for action_item in action_arr:
        for existing_action_item in target_arr:
            if action_item.action_name == existing_action_item.action_name:
                return action_item.action_name
        target_arr.append(action_item)
    return None


# pylint: disable=too-many-arguments, too-many-locals
# Rationale:
#   too-many-arguments, too-many-locals:
#     This function needs to load multiple kinds of data from configuration
#     files simultaneously. It is therefore hard to reduce the number of
#     arguments and variables it needs without harming readability.
def parse_config_file(
    config_file: Path,
    temp_action_list: list[PrivleapAction],
    temp_persistent_user_list: list[str],
    temp_allowed_user_list: list[str],
    temp_allowed_group_list: list[str],
    temp_expected_disallowed_user_list: list[str],
) -> bool:
    """
    Parses a single config file.
    """

    config_result: ConfigData | str
    action_arr: list[PrivleapAction]
    persistent_user_arr: list[str]
    allowed_user_arr: list[str]
    allowed_group_arr: list[str]
    expected_disallowed_user_arr: list[str]

    config_result = PrivleapCommon.parse_config_file(config_file)
    if isinstance(config_result, str):
        if PrivleapdGlobal.check_config_mode:
            print(config_result, file=sys.stderr)
        else:
            logging.error("Error parsing config: '%s'", config_result)
        return False
    action_arr = config_result[0]
    persistent_user_arr = config_result[1]
    allowed_user_arr = config_result[2]
    allowed_group_arr = config_result[3]
    expected_disallowed_user_arr = config_result[4]
    duplicate_action_name: str | None = extend_action_list(
        action_arr, temp_action_list
    )
    if duplicate_action_name is not None:
        duplicate_action_error = PrivleapCommon.find_bad_config_header(
            config_file, duplicate_action_name, "Duplicate action found:"
        )
        if PrivleapdGlobal.check_config_mode:
            print(duplicate_action_error, file=sys.stderr)
        else:
            logging.error("Error parsing config: '%s'", duplicate_action_error)
        return False
    for persistent_user_item in persistent_user_arr:
        # Note, parse_config_file() normalizes usernames for us.
        append_if_not_in(persistent_user_item, temp_persistent_user_list)
        # Persistent users are automatically allowed users too.
        append_if_not_in(persistent_user_item, temp_allowed_user_list)
        # It isn't an error for duplicate persistent users to be
        # defined, we just skip over the duplicates.
    for allowed_user_item in allowed_user_arr:
        append_if_not_in(allowed_user_item, temp_allowed_user_list)
    for allowed_group_item in allowed_group_arr:
        append_if_not_in(allowed_group_item, temp_allowed_group_list)
    for expected_disallowed_user_item in expected_disallowed_user_arr:
        append_if_not_in(
            expected_disallowed_user_item, temp_expected_disallowed_user_list
        )
    return True


def str_list_quote_and_comma_delimit(str_list: list[str]) -> str:
    """
    Turns a string list like ["abc", "def", "ghi"] into a string like
    "'abc', 'def', 'ghi'".
    """

    out_str: str = ""
    item_end_idx: int = len(str_list) - 1
    for item_idx, item in enumerate(str_list):
        out_str += f"'{item}'"
        if item_idx != item_end_idx:
            out_str += ", "
    return out_str


def parse_config_files() -> bool:
    """
    Parses all config files under /etc/privleap/conf.d.
    """

    config_file_list: list[Path] = []
    temp_action_list: list[PrivleapAction] = []
    temp_persistent_user_list: list[str] = []
    temp_allowed_user_list: list[str] = []
    temp_allowed_group_list: list[str] = []
    temp_expected_disallowed_user_list: list[str] = []

    for config_dir in PrivleapdGlobal.config_dir_list:
        temp_config_file_list: list[Path] = []
        if not config_dir.is_dir(follow_symlinks=False):
            if not PrivleapdGlobal.check_config_mode:
                ## Don't print this info when checking config, it's confusing
                ## and breaks systemcheck.
                logging.info(
                    "Config directory '%s' does not exist, skipping.",
                    str(config_dir),
                )
            continue
        if not PrivleapCommon.check_secure_file_permissions(str(config_dir)):
            logging.warning(
                "Config directory '%s' exists but has insecure permissions, "
                "ignoring all files in this directory.",
                str(config_dir),
            )
            continue

        for config_file in config_dir.iterdir():
            if not config_file.is_file() or not config_file.name.endswith(
                ".conf"
            ):
                ## This is not a validating filter, the actual rules for
                ## config file names are stricter than just "must end in
                ## .conf". However, this lets us filter out things that are
                ## obviously not config files, so that we can warn about
                ## things that look like config files but are named
                ## incorrectly.
                continue
            temp_config_file_list.append(config_file)
        temp_config_file_list.sort()
        config_file_list.extend(temp_config_file_list)

    if len(config_file_list) == 0:
        logging.error(
            "No valid configuration files found! Checked paths: %s",
            str_list_quote_and_comma_delimit(
                [str(x) for x in PrivleapdGlobal.config_dir_list]
            ),
        )
        return False

    for config_file in config_file_list:
        if not config_file.is_file():
            logging.warning(
                "Config file '%s' unexpectedly no longer exists, skipping.",
                str(config_file),
            )
            continue

        if not PrivleapCommon.validate_id(
            str(config_file), PrivleapValidateType.CONFIG_FILE
        ):
            logging.warning(
                "Config file '%s' has an illegal name, skipping.",
                str(config_file),
            )
            continue

        try:
            ## Permission checks on each individual config file are done by
            ## PrivleapCommon.parse_config_file() *after* the files are
            ## opened. This allows us to permit symlinks in the config
            ## directory without having a TOCTOU vulnerability.
            if not parse_config_file(
                config_file,
                temp_action_list,
                temp_persistent_user_list,
                temp_allowed_user_list,
                temp_allowed_group_list,
                temp_expected_disallowed_user_list,
            ):
                return False
        except Exception as e:
            logging.error(
                "Failed to load config file '%s'!", str(config_file), exc_info=e
            )
            return False
    PrivleapdGlobal.action_list = temp_action_list
    PrivleapdGlobal.persistent_user_list = temp_persistent_user_list
    PrivleapdGlobal.allowed_user_list = temp_allowed_user_list
    PrivleapdGlobal.allowed_group_list = temp_allowed_group_list
    PrivleapdGlobal.expected_disallowed_user_list = (
        temp_expected_disallowed_user_list
    )
    return True


def populate_state_dir() -> None:
    """
    Creates the state dir and PID file.
    """

    if not PrivleapCommon.state_dir.exists():
        try:
            PrivleapCommon.state_dir.mkdir(parents=True)
            PrivleapCommon.state_dir.chmod(0o755)
        except Exception as e:
            logging.critical(
                "Cannot create '%s'!",
                str(PrivleapCommon.state_dir),
                exc_info=e,
            )
            sys.exit(1)
    else:
        logging.critical(
            "Directory '%s' should not exist yet, but does!",
            str(PrivleapCommon.state_dir),
        )
        sys.exit(1)

    if not PrivleapCommon.comm_dir.exists():
        try:
            PrivleapCommon.comm_dir.mkdir(parents=True)
            PrivleapCommon.comm_dir.chmod(0o755)
        except Exception as e:
            logging.critical(
                "Cannot create '%s'!",
                str(PrivleapCommon.comm_dir),
                exc_info=e,
            )
            sys.exit(1)
    else:
        logging.critical(
            "Directory '%s' should not exist yet, but does!",
            str(PrivleapCommon.comm_dir),
        )
        sys.exit(1)

    try:
        with open(
            PrivleapdGlobal.pid_file_path, "w", encoding="utf-8"
        ) as pid_file:
            pid_file.write(str(os.getpid()) + "\n")
        PrivleapdGlobal.pid_file_path.chmod(0o644)
    except Exception as e:
        logging.critical(
            "Cannot create PID file at '%s'!",
            str(PrivleapdGlobal.pid_file_path),
            exc_info=e,
        )
        sys.exit(1)


def open_control_socket() -> None:
    """
    Opens the control socket. Privileged clients can connect to this socket to
      request that privleapd create or destroy comm sockets used for
      communicating with unprivileged users.
    """

    try:
        control_socket: PrivleapSocket = PrivleapSocket(
            PrivleapSocketType.CONTROL
        )
    except Exception as e:
        logging.critical("Failed to open control socket!", exc_info=e)
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
            comm_socket: PrivleapSocket = PrivleapSocket(
                PrivleapSocketType.COMMUNICATION, user_name
            )
            PrivleapdGlobal.socket_list.append(comm_socket)
            # We intentionally don't log the creation of persistent user sockets
            # since for one, doing so would needlessly clutter the system logs
            # (the list of persistent users can be determined by just looking
            # at privleap's config), and for two, privleap doesn't output log
            # information during early startup unless something is wrong. The
            # test suite depends on this behavior, so it's not something we want
            # to break unless necessary.
        except Exception as e:
            logging.error(
                "Failed to create persistent socket for account '%s'!",
                user_name,
                exc_info=e,
            )
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
        ready_socket_list: Tuple[list[int], list[int], list[int]] = (
            select.select(
                [
                    sock_obj.backend_socket.fileno()
                    for sock_obj in PrivleapdGlobal.socket_list
                    if sock_obj.backend_socket is not None
                ],
                [],
                [],
                5,
            )
        )
        PrivleapdGlobal.sdnotify_object.notify("WATCHDOG=1")
        for ready_socket_fileno in ready_socket_list[0]:
            ready_sock_obj: PrivleapSocket | None = None
            for sock_obj in PrivleapdGlobal.socket_list:
                assert sock_obj.backend_socket is not None
                if sock_obj.backend_socket.fileno() == ready_socket_fileno:
                    ready_sock_obj = sock_obj
                    break
            if ready_sock_obj is None:
                logging.critical("privleapd lost track of a socket!")
                sys.exit(1)
            if ready_sock_obj.socket_type == PrivleapSocketType.CONTROL:
                handle_control_session(ready_sock_obj)
            else:
                comm_thread: Thread = Thread(
                    target=handle_comm_session, args=[ready_sock_obj]
                )
                comm_thread.start()


def print_usage() -> None:
    """
    Print usage information.
    """
    print(
        """privleapd: privleap backend server
Usage:
  privleapd [-C|--check-config] [-h|--help|-?]
Options:
  -C, --check-config: Check configuration for validity.
  -h, --help, -?: Print usage information.
If run without any options specified, the server will start normally.""",
        file=sys.stderr,
    )


def main() -> NoReturn:
    """
    Main function.
    """

    ## Set restrictive umask to prevent any file permission vulnerability
    ## window during socket creation, this denies all privileges for
    ## non-owners.
    PrivleapdGlobal.old_umask = os.umask(0o077)

    logging.basicConfig(
        format="%(funcName)s: %(levelname)s: %(message)s", level=logging.INFO
    )
    for idx, arg in enumerate(sys.argv):
        if idx == 0:
            continue
        if arg == "--test":
            PrivleapdGlobal.test_mode = True
        elif arg in ("-C", "--check-config"):
            PrivleapdGlobal.check_config_mode = True
        elif arg in ("-h", "--help", "-?"):
            print_usage()
            sys.exit(0)
        else:
            print(
                f"Unrecognized argument {repr(arg)}, try 'privleapd --help' "
                "for usage info",
                file=sys.stderr,
            )
            sys.exit(1)

    if PrivleapdGlobal.check_config_mode:
        if not parse_config_files():
            sys.exit(1)
        sys.exit(0)

    ensure_running_as_root()
    verify_not_running_twice()
    cleanup_old_state_dir()
    if not parse_config_files():
        logging.critical("Failed initial config load!")
        sys.exit(1)
    populate_state_dir()
    open_control_socket()
    open_persistent_comm_sockets()
    PrivleapdGlobal.sdnotify_object.notify("READY=1")
    PrivleapdGlobal.sdnotify_object.notify("STATUS=Fully started")
    if PrivleapdGlobal.test_mode:
        Path("/tmp/privleapd-ready-for-test").touch()
    main_loop()


if __name__ == "__main__":
    main()
