#!/usr/bin/python3 -su

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,global-statement,too-many-lines
# Rationale:
#   broad-exception-caught: We use broad exception catching for general-purpose
#     error handlers.
#   global-statement: Only used for the assert count variables, not a problem.
#   too-many-lines: Breaking up this file is not a priority at the moment.

"""
run_test.py - Tests for privleap. This is implemented as an entire program as
  unit testing would not exercise the code sufficiently. This runs through a
  wide variety of real-world-like tests to ensure all components of privleap
  behave as expected. This should be run using an autopkgtest.

WARNING: These tests are designed to not damage the system they are ran on,
  but the chances of system damage occurring when running this script is
  non-zero! Do not run these tests directly, use run_autopkgtest instead.
"""

import os
import sys
import logging
import subprocess
import shutil
import socket
import time
import signal
from pathlib import Path
from typing import NoReturn, Tuple, IO, TypeAlias
from collections.abc import Callable

# import privleap as pl

import privleap.privleap as pl
import run_test_util as util
from run_test_util import stop_privleapd_subprocess
from run_test_util import PlTestGlobal, PlTestData

leapctl_asserts_passed: int = 0
leapctl_asserts_failed: int = 0
leaprun_asserts_passed: int = 0
leaprun_asserts_failed: int = 0
privleapd_asserts_passed: int = 0
privleapd_asserts_failed: int = 0

SelectInfo: TypeAlias = Tuple[list[IO[bytes]], list[IO[bytes]], list[IO[bytes]]]


def test_if_path_exists(path_str: str) -> bool:
    """
    Tests to see if a path exists.
    """

    path: Path = Path(path_str)
    if path.exists():
        return True
    return False


def test_if_path_not_exists(path_str: str) -> bool:
    """
    Tests to see if a path does not exist.
    """

    path: Path = Path(path_str)
    if not path.exists():
        return True
    return False


def make_blocker_socket(path_str: str) -> bool:
    """
    Creates a dangling socket for blocking connections.
    """

    try:
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(path_str)
        sock.listen(1)
        sock.close()
    except Exception:
        return False
    return True


def try_remove_file(path_str: str) -> bool:
    """
    Tries to remove a file, returning a boolean indicating if the attempts was
      successful or not.
    """

    try:
        os.unlink(path_str)
    except Exception:
        return False
    return True


def init_fake_server_dirs() -> None:
    """
    Initializes directories used by privleapd, so a fake server can run.
    """

    if PlTestGlobal.privleap_state_dir.exists():
        shutil.rmtree(PlTestGlobal.privleap_state_dir)
    PlTestGlobal.privleap_state_comm_dir.mkdir(parents=True)


def leapctl_assert_command(
    command_data: list[str],
    exit_code: int,
    stdout_data: bytes = b"",
    stderr_data: bytes = b"",
) -> None:
    """
    Runs a command for leapctl tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global leapctl_asserts_passed
    global leapctl_asserts_failed
    if util.assert_command_result(
        command_data, exit_code, stdout_data, stderr_data
    ):
        logging.info("Assert passed: %s", command_data)
        leapctl_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        leapctl_asserts_failed += 1
        PlTestGlobal.all_asserts_passed = False


def leapctl_assert_function(
    target_function: Callable[[str], bool], func_arg: str, assert_name: str
) -> None:
    """
    Runs a function that returns a boolean, passing the given string argument.
      Records the result as a passed or failed assertion.
    """

    global leapctl_asserts_passed
    global leapctl_asserts_failed
    if target_function(func_arg):
        logging.info("Assert passed: %s", assert_name)
        leapctl_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", assert_name)
        leapctl_asserts_failed += 1
        PlTestGlobal.all_asserts_passed = False


def leapctl_create_deleteme_user(bogus: str) -> bool:
    """
    Creates a user account for testing deleting a comm socket for a user that
      doesn't exist anymore.
    """

    if bogus != "":
        return False
    try:
        subprocess.run(["useradd", "-m", "deleteme"], check=True)
    except Exception:
        return False
    return True


def leapctl_delete_deleteme_user(bogus: str) -> bool:
    """
    Deletes a user account for testing deleting a comm socket for a user that
      doesn't exist anymore.
    """

    if bogus != "":
        return False
    try:
        subprocess.run(["deluser", "deleteme"], check=True)
    except Exception:
        return False
    return True


def leapctl_server_error_test(bogus: str) -> bool:
    """
    Tests leapctl against a fake server that always errors out regardless of
      the requested action.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    control_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.CONTROL
    )
    with subprocess.Popen(
        ["leapctl", "--create", PlTestGlobal.test_username],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as leapctl_proc:
        control_session = control_socket.get_session()
        control_session.get_msg()
        control_session.send_msg(pl.PrivleapControlServerControlErrorMsg())
        control_session.close_session()
        assert control_socket.backend_socket is not None
        control_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        control_socket.backend_socket.close()
        os.unlink(Path(PlTestGlobal.privleap_state_dir, "control"))
        leapctl_result: Tuple[bytes, bytes] = leapctl_proc.communicate()
        if leapctl_result[1] == PlTestData.test_username_create_error:
            return True
    return False


def leapctl_server_cutoff_test(bogus: str) -> bool:
    """
    Tests leapctl against a fake server that always immediately disconnects any
      incoming connection.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    control_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.CONTROL
    )
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for _ in range(5):
        with subprocess.Popen(
            ["leapctl", "--create", PlTestGlobal.test_username],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as leapctl_proc:
            control_session = control_socket.get_session()
            control_session.close_session()
            assert control_socket.backend_socket is not None
            leapctl_result: Tuple[bytes, bytes] = leapctl_proc.communicate()
            if leapctl_result[1] == PlTestData.privleapd_invalid_response:
                control_socket.backend_socket.shutdown(socket.SHUT_RDWR)
                control_socket.backend_socket.close()
                os.unlink(Path(PlTestGlobal.privleap_state_dir, "control"))
                return True
    return False


def run_leapctl_tests() -> None:
    """
    Runs all tests on the leapctl executable.
    """

    # ---
    util.start_privleapd_subprocess([])
    leapctl_assert_command(
        ["leapctl", "--create", "nonexistent"],
        exit_code=1,
        stderr_data=PlTestData.specified_user_missing,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--destroy", "nonexistent"],
        exit_code=0,
        stdout_data=PlTestData.nonexistent_socket_missing,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "_apt"],
        exit_code=0,
        stdout_data=PlTestData.apt_socket_created,
    )
    leapctl_assert_function(
        test_if_path_exists,
        str(Path(PlTestGlobal.privleap_state_dir, "comm", "_apt")),
        "Ensure _apt socket exists",
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--destroy", "_apt"],
        exit_code=0,
        stdout_data=PlTestData.apt_socket_destroyed,
    )
    leapctl_assert_function(
        test_if_path_not_exists,
        str(Path(PlTestGlobal.privleap_state_dir, "comm", "_apt")),
        "Ensure _apt socket does not exist",
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    leapctl_assert_function(
        test_if_path_exists,
        str(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        ),
        "Ensure test user socket exists",
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--destroy", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_destroyed,
    )
    leapctl_assert_function(
        test_if_path_not_exists,
        str(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        ),
        "Ensure test user socket does not exist",
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--destroy", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_missing,
    )
    # ---
    leapctl_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leapctl",
            "--create",
            PlTestGlobal.test_username,
        ],
        exit_code=1,
        stderr_data=PlTestData.privleapd_connection_failed,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    leapctl_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_exists,
    )
    # ---
    leapctl_assert_function(
        make_blocker_socket,
        str(Path(PlTestGlobal.privleap_state_dir, "comm", "root")),
        "Create blocker socket for account 'root'",
    )
    leapctl_assert_command(
        ["leapctl", "--create", "root"],
        exit_code=1,
        stderr_data=PlTestData.root_create_error,
    )
    leapctl_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_state_dir, "comm", "root")),
        "Remove blocker socket for account 'root'",
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_created,
    )
    leapctl_assert_command(
        ["leapctl", "--destroy", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_destroyed,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "1"],
        exit_code=0,
        stdout_data=PlTestData.daemon_socket_created,
    )
    leapctl_assert_command(
        ["leapctl", "--destroy", "1"],
        exit_code=0,
        stdout_data=PlTestData.daemon_socket_destroyed,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_created,
    )
    leapctl_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_state_dir, "comm", "root")),
        "Remove active socket for account root",
    )
    leapctl_assert_command(
        ["leapctl", "--destroy", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_destroyed,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--destroy", "sys"],
        exit_code=0,
        stdout_data=PlTestData.cannot_destroy_persistent_sys_socket,
    )
    # ---
    util.stop_privleapd_subprocess()
    leapctl_assert_function(
        leapctl_create_deleteme_user,
        "",
        "Create user for deleted user socket destroy test",
    )
    util.start_privleapd_subprocess([])
    leapctl_assert_command(
        ["leapctl", "--create", "deleteme"],
        exit_code=0,
        stdout_data=PlTestData.deleteme_socket_created,
    )
    leapctl_assert_function(
        leapctl_delete_deleteme_user,
        "",
        "Delete user for deleted user socket destroy test",
    )
    leapctl_assert_command(
        ["leapctl", "--destroy", "deleteme"],
        exit_code=0,
        stdout_data=PlTestData.deleteme_socket_destroyed,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "man"],
        exit_code=2,
        stderr_data=PlTestData.man_socket_not_permitted,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "irc"],
        exit_code=0,
        stdout_data=PlTestData.irc_expected_socket_not_permitted,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "news"],
        exit_code=0,
        stdout_data=PlTestData.news_expected_socket_not_permitted,
    )
    # ---
    leapctl_assert_command(
        ["leapctl", "--create", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_created,
    )
    # ---
    util.stop_privleapd_subprocess()
    leapctl_assert_function(
        leapctl_server_error_test,
        "",
        "Test leapctl against fake server that always errors out",
    )
    # ---
    leapctl_assert_function(
        leapctl_server_cutoff_test,
        "",
        "Test leapctl against fake server that always abruptly disconnects",
    )
    # ---
    leapctl_assert_command(
        ["leapctl"], exit_code=1, stdout_data=PlTestData.leapctl_help
    )
    # ---

    logging.info(
        "leapctl passed asserts: %s, failed asserts: %s",
        leapctl_asserts_passed,
        leapctl_asserts_failed,
    )


def leaprun_assert_command(
    command_data: list[str],
    exit_code: int,
    stdout_data: bytes = b"",
    stderr_data: bytes = b"",
    filter_func: Callable[[bytes, bool], bytes] | None = None,
) -> None:
    """
    Runs a command for leaprun tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global leaprun_asserts_passed
    global leaprun_asserts_failed
    if util.assert_command_result(
        command_data, exit_code, stdout_data, stderr_data, filter_func
    ):
        logging.info("Assert passed: %s", command_data)
        leaprun_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        leaprun_asserts_failed += 1
        PlTestGlobal.all_asserts_passed = False


def leaprun_assert_function(
    target_function: Callable[[str], bool], func_arg: str, assert_name: str
) -> None:
    """
    Runs a function that returns a boolean, passing the given string argument.
      Records the result as a passed or failed assertion.
    """

    global leaprun_asserts_passed
    global leaprun_asserts_failed
    if target_function(func_arg):
        logging.info("Assert passed: %s", assert_name)
        leaprun_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", assert_name)
        leaprun_asserts_failed += 1
        PlTestGlobal.all_asserts_passed = False


def leaprun_server_invalid_response_test(bogus: str) -> bool:
    """
    Tests how leapctl handles an invalid message being returned by the server.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.COMMUNICATION,
        user_name=PlTestGlobal.test_username,
    )
    with subprocess.Popen(
        ["sudo", "-u", PlTestGlobal.test_username, "leaprun", "test-act-free"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as leaprun_proc:
        comm_session = comm_socket.get_session()
        comm_session.get_msg()
        # noinspection PyUnresolvedReferences
        # noinspection PyProtectedMember
        # pylint: disable=protected-access
        # Rationale:
        #   protected-access: privleap prevents us from sending incorrect
        #     message types. However, this code tests what happens when an
        #     incorrect message type is sent anyway, so we have to bypass the
        #     protections.
        comm_session._PrivleapSession__send_msg(  # type: ignore [attr-defined]
            pl.PrivleapControlServerNouserMsg()
        )
        comm_session.close_session()
        assert comm_socket.backend_socket is not None
        comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        comm_socket.backend_socket.close()
        os.unlink(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        )
        leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
        if leaprun_result[1] == PlTestData.privleapd_invalid_response:
            return True
    return False


def leaprun_server_late_cutoff_test(bogus: str) -> bool:
    """
    Tests how leapctl handles the server cutting it off after reading a message.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.COMMUNICATION,
        user_name=PlTestGlobal.test_username,
    )
    with subprocess.Popen(
        ["sudo", "-u", PlTestGlobal.test_username, "leaprun", "test-act-free"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as leaprun_proc:
        comm_session = comm_socket.get_session()
        comm_session.get_msg()
        comm_session.close_session()
        assert comm_socket.backend_socket is not None
        comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        comm_socket.backend_socket.close()
        os.unlink(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        )
        leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
        if leaprun_result[1] == PlTestData.privleapd_invalid_response:
            return True
    return False


def leaprun_filter_env_var_test_stdout(
    stdout_data: bytes, is_stdout: bool
) -> bytes:
    """
    Filters out non-deterministic environment variables from the output of the
      leaprun env var tests.
    """

    if not is_stdout:
        return stdout_data
    stdout_parts: list[bytes] = stdout_data.split(b"\n")
    stdout_parts_out: list[bytes] = []
    for stdout_part in stdout_parts:
        if stdout_part == b"":
            continue
        if (
            stdout_part.startswith(b"ADTTMP=")
            or stdout_part.startswith(b"AUTOPKGTEST_ARTIFACTS=")
            or stdout_part.startswith(b"AUTOPKGTEST_TMP=")
            or stdout_part.startswith(b"ADT_ARTIFACTS=")
        ):
            continue
        stdout_parts_out.append(stdout_part)
    return b"\n".join(stdout_parts_out) + b"\n"


# pylint: disable=too-many-statements
# Rationale:
#   too-many-statements: This is a dispatch function for tests, cannot be split
#     up.
def run_leaprun_tests() -> None:
    """
    Runs all tests on the leaprun executable.
    """

    # ---
    util.start_privleapd_subprocess([])
    leaprun_assert_command(
        ["sudo", "-u", PlTestGlobal.test_username, "leaprun", "test"],
        exit_code=1,
        stderr_data=PlTestData.privleapd_connection_failed,
    )
    # ---
    leaprun_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    util.stop_privleapd_subprocess()
    leaprun_assert_command(
        ["sudo", "-u", PlTestGlobal.test_username, "leaprun", "test-act-free"],
        exit_code=1,
        stderr_data=PlTestData.privleapd_connection_failed,
    )
    # ---
    util.start_privleapd_subprocess([])
    leaprun_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-nonexistent",
        ],
        exit_code=1,
        stderr_data=PlTestData.test_act_nonexistent_unauthorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-userrestrict",
        ],
        exit_code=1,
        stderr_data=PlTestData.test_act_userrestrict_unauthorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-grouprestrict",
        ],
        exit_code=1,
        stderr_data=PlTestData.test_act_grouprestrict_unauthorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-grouppermit-userrestrict",
        ],
        exit_code=0,
        stdout_data=b"test-act-grouppermit-userrestrict\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-grouprestrict-userpermit",
        ],
        exit_code=0,
        stdout_data=b"test-act-grouprestrict-userpermit\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-target-user",
        ],
        exit_code=0,
        stdout_data=PlTestData.test_act_target_user,
    )
    # ---
    leaprun_assert_command(
        ["leapctl", "--create", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_created,
    )
    leaprun_assert_command(
        ["leaprun", "test-act-target-group"],
        exit_code=0,
        stdout_data=PlTestData.test_act_target_group,
    )
    # ---
    leaprun_assert_command(
        ["leaprun", "test-act-userrestrict"],
        exit_code=0,
        stdout_data=b"test-act-userrestrict\n",
    )
    leaprun_assert_command(
        ["leapctl", "--destroy", "root"],
        exit_code=0,
        stdout_data=PlTestData.root_socket_destroyed,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-target-user-and-group",
        ],
        exit_code=0,
        stdout_data=PlTestData.test_act_target_user_and_group,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-missing-user",
        ],
        exit_code=0,
        stdout_data=b"test-act-missing-user\n",
    )
    # ---
    leaprun_assert_command(
        ["sudo", "-u", PlTestGlobal.test_username, "leaprun", "test-act-free"],
        exit_code=0,
        stdout_data=b"test-act-free\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-userpermit",
        ],
        exit_code=0,
        stdout_data=b"test-act-userpermit\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-multi-equals",
        ],
        exit_code=0,
        stdout_data=b"abc=def\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-grouppermit",
        ],
        exit_code=0,
        stdout_data=b"test-act-grouppermit\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-grouppermit-userpermit",
        ],
        exit_code=0,
        stdout_data=b"test-act-grouppermit-userpermit\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-sudopermit",
        ],
        exit_code=0,
        stdout_data=b"test-act-sudopermit\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-multiuser-permit",
        ],
        exit_code=0,
        stdout_data=b"test-act-multiuser-permit\n",
    )
    leaprun_assert_command(
        ["sudo", "-u", "sys", "leaprun", "test-act-multiuser-permit"],
        exit_code=0,
        stdout_data=b"test-act-multiuser-permit\n",
    )
    leaprun_assert_command(
        ["sudo", "-u", "messagebus", "leaprun", "test-act-multiuser-permit"],
        exit_code=0,
        stdout_data=b"test-act-multiuser-permit\n",
    )
    leaprun_assert_command(
        ["sudo", "-u", "bin", "leaprun", "test-act-multiuser-permit"],
        exit_code=1,
        stderr_data=PlTestData.test_act_multiuser_permit_unauthorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-multigroup-permit",
        ],
        exit_code=0,
        stdout_data=b"test-act-multigroup-permit\n",
    )
    leaprun_assert_command(
        ["sudo", "-u", "sys", "leaprun", "test-act-multigroup-permit"],
        exit_code=0,
        stdout_data=b"test-act-multigroup-permit\n",
    )
    leaprun_assert_command(
        ["sudo", "-u", "messagebus", "leaprun", "test-act-multigroup-permit"],
        exit_code=0,
        stdout_data=b"test-act-multigroup-permit\n",
    )
    leaprun_assert_command(
        ["sudo", "-u", "bin", "leaprun", "test-act-multigroup-permit"],
        exit_code=1,
        stderr_data=PlTestData.test_act_multigroup_permit_unauthorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-multiuser-multigroup-permit",
        ],
        exit_code=0,
        stdout_data=b"test-act-multiuser-multigroup-permit\n",
    )
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            "sys",
            "leaprun",
            "test-act-multiuser-multigroup-permit",
        ],
        exit_code=0,
        stdout_data=b"test-act-multiuser-multigroup-permit\n",
    )
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            "messagebus",
            "leaprun",
            "test-act-multiuser-multigroup-permit",
        ],
        exit_code=0,
        stdout_data=b"test-act-multiuser-multigroup-permit\n",
    )
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            "bin",
            "leaprun",
            "test-act-multiuser-multigroup-permit",
        ],
        exit_code=1,
        stderr_data=PlTestData.test_act_multiuser_multigroup_permit_unauthorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-exit240",
        ],
        exit_code=240,
        stdout_data=b"test-act-exit240\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-stderr",
        ],
        exit_code=0,
        stderr_data=b"test-act-stderr\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-stdout-stderr-interleaved",
        ],
        exit_code=0,
        stdout_data=b"stdout00\nstdout01\n",
        stderr_data=b"stderr00\nstderr01\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-rootdata",
        ],
        exit_code=0,
        stdout_data=PlTestData.test_act_rootdata,
        filter_func=leaprun_filter_env_var_test_stdout,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-userdata",
        ],
        exit_code=0,
        stdout_data=PlTestData.test_act_userdata,
        filter_func=leaprun_filter_env_var_test_stdout,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "--check",
            "test-act-free",
        ],
        exit_code=0,
        stdout_data=PlTestData.test_act_free_authorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "-c",
            "--",
            "test-act-free",
        ],
        exit_code=0,
        stdout_data=PlTestData.test_act_free_authorized,
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "--check",
            "test-act-userrestrict",
        ],
        exit_code=1,
        stderr_data=PlTestData.test_act_userrestrict_unauthorized,
    )
    # ---
    util.stop_privleapd_subprocess()
    leaprun_assert_function(
        leaprun_server_invalid_response_test,
        "",
        "Leaprun invalid response test",
    )
    # ---
    leaprun_assert_function(
        leaprun_server_late_cutoff_test, "", "Leaprun server late cutoff test"
    )
    # ---
    util.start_privleapd_subprocess([])
    leaprun_assert_function(
        write_new_config_file,
        "added_actions_config_file",
        "Write config file with added actions",
    )
    leaprun_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    leaprun_assert_command(
        ["leapctl", "--reload"],
        exit_code=0,
        stdout_data=b"privleapd configuration reload successful.\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-added1",
        ],
        exit_code=0,
        stdout_data=b"test-act-added1\n",
    )
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-added2",
        ],
        exit_code=0,
        stdout_data=b"test-act-added2\n",
    )
    # ---
    leaprun_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "added_actions.conf")),
        "Remove added actions config file",
    )
    leaprun_assert_command(
        ["leapctl", "--reload"],
        exit_code=0,
        stdout_data=b"privleapd configuration reload successful.\n",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-added1",
        ],
        exit_code=1,
        stderr_data=b"ERROR: You are unauthorized to run action "
        + b"'test-act-added1'.\n",
    )
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-added2",
        ],
        exit_code=1,
        stderr_data=b"ERROR: You are unauthorized to run action "
        + b"'test-act-added2'.\n",
    )
    # ---
    leaprun_assert_function(
        write_new_config_file,
        "added_actions_bad_config_file",
        "Write bad config file with added actions",
    )
    leaprun_assert_command(
        ["leapctl", "--reload"],
        exit_code=1,
        stderr_data=b"ERROR: privleapd failed to reload configuration!\n",
    )
    leaprun_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "added_actions_bad.conf")),
        "Remove bad added actions config file",
    )
    # ---
    leaprun_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "--",
            "test-act-grouppermit-userrestrict",
        ],
        exit_code=0,
        stdout_data=b"test-act-grouppermit-userrestrict\n",
    )
    # ---

    logging.info(
        "leaprun passed asserts: %s, failed asserts: %s",
        leaprun_asserts_passed,
        leaprun_asserts_failed,
    )


def write_config_file_with_bad_name(bogus: str) -> bool:
    """
    Writes a config file with an invalid name. privleapd should ignore this.
    """

    if bogus != "":
        return False
    try:
        with open(
            Path(PlTestGlobal.privleap_conf_dir, "invalid%config.conf"),
            "w",
            encoding="utf-8",
        ) as config_file:
            config_file.write(PlTestData.invalid_filename_test_config_file)
        return True
    except Exception:
        return False


def write_new_config_file(bad_config_file: str) -> bool:
    """
    Writes a config file other than the default unit-test.conf file. Used for
      testing various things that involve changing configuration.
    """

    target_path: Path
    target_contents: str
    match bad_config_file:
        case "crash_config_file":
            target_path = Path(PlTestGlobal.privleap_conf_dir, "crash.conf")
            target_contents = PlTestData.crash_config_file
        case "duplicate_action_config_file":
            target_path = Path(PlTestGlobal.privleap_conf_dir, "duplicate.conf")
            target_contents = PlTestData.duplicate_action_config_file
        case "wrongorder_config_file":
            target_path = Path(
                PlTestGlobal.privleap_conf_dir, "wrongorder.conf"
            )
            target_contents = PlTestData.wrongorder_config_file
        case "duplicate_keys_config_file":
            target_path = Path(PlTestGlobal.privleap_conf_dir, "dupkeys.conf")
            target_contents = PlTestData.duplicate_keys_config_file
        case "absent_command_directive_config_file":
            target_path = Path(PlTestGlobal.privleap_conf_dir, "absent.conf")
            target_contents = PlTestData.absent_command_directive_config_file
        case "invalid_action_config_file":
            target_path = Path(
                PlTestGlobal.privleap_conf_dir, "invalidaction.conf"
            )
            target_contents = PlTestData.invalid_action_config_file
        case "added_actions_config_file":
            target_path = Path(
                PlTestGlobal.privleap_conf_dir, "added_actions.conf"
            )
            target_contents = PlTestData.added_actions_config_file
        case "added_actions_bad_config_file":
            target_path = Path(
                PlTestGlobal.privleap_conf_dir, "added_actions_bad.conf"
            )
            target_contents = PlTestData.added_actions_bad_config_file
        case "unrecognized_header_config_file":
            target_path = Path(
                PlTestGlobal.privleap_conf_dir, "unrec_header.conf"
            )
            target_contents = PlTestData.unrecognized_header_config_file
        case "missing_auth_config_file":
            target_path = Path(
                PlTestGlobal.privleap_conf_dir, "missing_auth.conf"
            )
            target_contents = PlTestData.missing_auth_config_file
        case _:
            return False

    try:
        with open(target_path, "w", encoding="utf-8") as config_file:
            config_file.write(target_contents)
            return True
    except Exception:
        return False


def privleapd_check_persistent_users_test(bogus: str) -> bool:
    """
    Ensures all persistent users configured in privleapd's test configuration
      have comm sockets created automatically.
    """

    if bogus != "":
        return False
    # This is duplicated from data in primary_test_config_file in
    # run_test_util.py, since part of the test in that config file is to ensure
    # the config parser can handle multiple [persistent-users] sections, making
    # it difficult to store the list of persistent users in a central location
    # that everything else uses.
    persistent_user_list: list[str] = ["sys", "bin", "uucp", "messagebus"]
    for user in persistent_user_list:
        if not Path("/run/privleapd/comm", user).exists():
            return False
    return True


def privleapd_bad_config_file_test(test_type: str) -> bool:
    """
    Tests how privleapd handles a bad config file.
    """

    expect_privleapd_stderr: list[str] = []
    match test_type:
        case "bad_config_file":
            expect_privleapd_stderr = PlTestData.bad_config_file_lines
        case "duplicate_action_config_file":
            expect_privleapd_stderr = (
                PlTestData.duplicate_actions_config_file_lines
            )
        case "wrongorder_config_file":
            expect_privleapd_stderr = PlTestData.wrongorder_config_file_lines
        case "duplicate_keys_config_file":
            expect_privleapd_stderr = (
                PlTestData.duplicate_keys_config_file_lines
            )
        case "absent_command_directive_config_file":
            expect_privleapd_stderr = (
                PlTestData.absent_command_directive_config_file_lines
            )
        case "invalid_action_config_file":
            expect_privleapd_stderr = (
                PlTestData.invalid_action_config_file_lines
            )
        case "unrecognized_header_config_file":
            expect_privleapd_stderr = (
                PlTestData.unrecognized_header_config_file_lines
            )
        case "missing_auth_config_file":
            expect_privleapd_stderr = PlTestData.missing_auth_config_file_lines
    util.start_privleapd_subprocess([], allow_error_output=True)
    if not util.compare_privleapd_stderr(expect_privleapd_stderr):
        stop_privleapd_subprocess()
        return False
    stop_privleapd_subprocess()
    return True


def privleapd_bad_config_file_check_test(bogus: str) -> bool:
    """
    Tests how privleapd handles a bad config file when using --check-config.
    """

    if bogus != "":
        return False
    util.start_privleapd_subprocess(["--check-config"], allow_error_output=True)
    if not util.compare_privleapd_stderr(
        PlTestData.bad_config_file_check_lines
    ):
        stop_privleapd_subprocess()
        return False
    stop_privleapd_subprocess()
    return True


def privleapd_control_disconnect_test(bogus: str) -> bool:
    """
    Tests how privleapd handles a control client that connects and then
      instantly disconnects.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.close_session()
    return util.compare_privleapd_stderr(PlTestData.control_disconnect_lines)


def privleapd_create_invalid_user_socket_test(bogus: str) -> bool:
    """
    Tests how privleapd handles a control client that requests a socket to be
      created for a user that does not exist.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(pl.PrivleapControlClientCreateMsg("nonexistent"))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(
        control_server_msg, pl.PrivleapControlServerControlErrorMsg
    ):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.control_create_invalid_user_socket_lines
    ):
        assert_success = False
    return assert_success


def privleapd_create_invalid_user_socket_and_bail_test(bogus: str) -> bool:
    """
    Tests how privleapd handles a control client that requests a socket to be
      created for a user that does not exist, and then disconnects before
      privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session=True
        )
        control_session.send_msg(
            pl.PrivleapControlClientCreateMsg("nonexistent")
        )
        control_session.close_session()
        if util.compare_privleapd_stderr(
            PlTestData.create_invalid_user_socket_and_bail_lines, quiet=i != 4
        ):
            return True
    return False


def privleapd_destroy_invalid_user_socket_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      destroyed for a user that does not exist.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(pl.PrivleapControlClientDestroyMsg("nonexistent"))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerNouserMsg):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.destroy_invalid_user_socket_lines
    ):
        assert_success = False
    return assert_success


def privleapd_create_user_socket_twice_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      created for the same (existing) user twice in a row.
    """
    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(
        pl.PrivleapControlClientCreateMsg(PlTestGlobal.test_username)
    )
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerOkMsg):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    control_session = pl.PrivleapSession(is_control_session=True)
    control_session.send_msg(
        pl.PrivleapControlClientCreateMsg(PlTestGlobal.test_username)
    )
    control_server_msg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerExistsMsg):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(PlTestData.create_user_socket_lines):
        assert_success = False
    return assert_success


def privleapd_create_existing_user_socket_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      created for a user that already has a socket created, and then disconnects
      before privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session=True
        )
        control_session.send_msg(
            pl.PrivleapControlClientCreateMsg(PlTestGlobal.test_username)
        )
        control_session.close_session()
        if util.compare_privleapd_stderr(
            PlTestData.create_existing_user_socket_and_bail_lines, quiet=i != 4
        ):
            return True
    return False


def privleapd_create_blocked_user_socket_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      created for a user that has a blocker socket in the way.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(
        pl.PrivleapControlClientCreateMsg(PlTestGlobal.test_username)
    )
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(
        control_server_msg, pl.PrivleapControlServerControlErrorMsg
    ):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.create_blocked_user_socket_lines
    ):
        assert_success = False
    return assert_success


def privleapd_create_blocked_user_socket_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      created for a user that has a blocker socket in the way, and then
      disconnects before privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session=True
        )
        control_session.send_msg(
            pl.PrivleapControlClientCreateMsg(PlTestGlobal.test_username)
        )
        control_session.close_session()
        if util.compare_privleapd_stderr(
            PlTestData.create_blocked_user_socket_and_bail_lines, quiet=i != 4
        ):
            return True
    return False


def privleapd_destroy_missing_user_socket_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      destroyed for a user who's socket on the filesystem has been deleted.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    try:
        os.unlink(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        )
    except Exception:
        return False
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(
        pl.PrivleapControlClientDestroyMsg(PlTestGlobal.test_username)
    )
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerOkMsg):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.destroy_missing_user_socket_lines
    ):
        assert_success = False
    return assert_success


def privleapd_create_expected_disallowed_socket_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      created for a user that is marked as "expected disallowed".
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(pl.PrivleapControlClientCreateMsg("irc"))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(
        control_server_msg, pl.PrivleapControlServerExpectedDisallowedUserMsg
    ):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.create_expected_disallowed_socket_lines
    ):
        assert_success = False
    return assert_success


def privleapd_destroy_user_socket_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      destroyed for a user with a socket in existence, and then disconnects
      before privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session=True
        )
        control_session.send_msg(
            pl.PrivleapControlClientCreateMsg(PlTestGlobal.test_username)
        )
        _ = control_session.get_msg()
        control_session.close_session()
        util.discard_privleapd_stderr()
        control_session = pl.PrivleapSession(is_control_session=True)
        control_session.send_msg(
            pl.PrivleapControlClientDestroyMsg(PlTestGlobal.test_username)
        )
        control_session.close_session()
        if util.compare_privleapd_stderr(
            PlTestData.destroy_user_socket_and_bail_lines, quiet=i != 4
        ):
            return True
    return False


def privleapd_destroy_bad_user_socket_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a control client that requests a socket to be
      destroyed for a user with a socket in existence, and then disconnects
      before privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session=True
        )
        control_session.send_msg(
            pl.PrivleapControlClientDestroyMsg(PlTestGlobal.test_username)
        )
        control_session.close_session()
        if util.compare_privleapd_stderr(
            PlTestData.destroy_bad_user_socket_and_bail_lines, quiet=i != 4
        ):
            return True
    return False


def privleapd_send_invalid_control_message_test(bogus: str) -> bool:
    """
    Test how privleapd handles an entirely invalid message sent by a control
      client.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    assert control_session.backend_socket is not None
    # privleap message packets are simply length-prefixed binary blobs, with the
    # length specified as a 4-byte big-endian integer.
    util.socket_send_raw_bytes(
        control_session.backend_socket, b"\x00\x00\x00\x0DBOB asdfghjkl"
    )
    control_session.close_session()
    if not util.compare_privleapd_stderr(
        PlTestData.send_invalid_control_message_lines
    ):
        return False
    return True


def privleapd_send_corrupted_control_message_test(bogus: str) -> bool:
    """
    Test how privleapd handles a corrupted message sent by a control client.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    assert control_session.backend_socket is not None
    # CREATE is only supposed to have a single parameter after it, the name of
    # the user to create a socket for. The "exploit" at the end is additional
    # data that isn't expected and should be rejected. The pun in "root exploit"
    # was not originally intended, but was too good to leave out :)
    util.socket_send_raw_bytes(
        control_session.backend_socket, b"\x00\x00\x00\x13CREATE root exploit"
    )
    control_session.close_session()
    if not util.compare_privleapd_stderr(
        PlTestData.send_corrupted_control_message_lines
    ):
        return False
    return True


def privleapd_bail_comm_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that immediately disconnects after
      connecting.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    comm_session.close_session()
    if not util.compare_privleapd_stderr(PlTestData.bail_comm_lines):
        return False
    return True


def privleapd_send_invalid_comm_message_test(bogus: str) -> bool:
    """
    Test how privleapd handles a corrupted message sent by a comm client.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    assert comm_session.backend_socket is not None
    # privleap message packets are simply length-prefixed binary blobs, with the
    # length specified as a 4-byte big-endian integer.
    util.socket_send_raw_bytes(
        comm_session.backend_socket, b"\x00\x00\x00\x0DBOB asdfghjkl"
    )
    comm_session.close_session()
    if not util.compare_privleapd_stderr(
        PlTestData.send_invalid_comm_message_lines
    ):
        return False
    return True


def privleapd_send_nonexistent_signal_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that requests a nonexistent action
      to be run, and then disconnects before privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        comm_session: pl.PrivleapSession = pl.PrivleapSession(
            PlTestGlobal.test_username
        )
        comm_session.send_msg(pl.PrivleapCommClientSignalMsg("nonexistent"))
        comm_session.close_session()
        part1_passed: bool = False
        part2_passed: bool = False
        if util.compare_privleapd_stderr(
            PlTestData.send_nonexistent_signal_and_bail_lines_part1,
            quiet=i != 4,
        ):
            part1_passed = True
        # privleapd waits about 3 seconds before sending the UNAUTHORIZED
        # message for security reasons
        time.sleep(3)
        if util.compare_privleapd_stderr(
            PlTestData.unauthorized_broken_pipe_lines, quiet=i != 4
        ):
            part2_passed = True
        if part1_passed and part2_passed:
            return True
    return False


def privleapd_send_userrestrict_signal_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that requests an action to be run
      that the user is not permitted to run, and then disconnects before
      privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        comm_session: pl.PrivleapSession = pl.PrivleapSession(
            PlTestGlobal.test_username
        )
        comm_session.send_msg(
            pl.PrivleapCommClientSignalMsg("test-act-userrestrict")
        )
        comm_session.close_session()
        part1_passed: bool = False
        part2_passed: bool = False
        if util.compare_privleapd_stderr(
            PlTestData.send_userrestrict_signal_and_bail_lines_part1,
            quiet=i != 4,
        ):
            part1_passed = True
        # privleapd waits about 3 seconds before sending the UNAUTHORIZED
        # message for security reasons
        time.sleep(3)
        if util.compare_privleapd_stderr(
            PlTestData.unauthorized_broken_pipe_lines, quiet=i != 4
        ):
            part2_passed = True
        if part1_passed and part2_passed:
            return True
    return False


def privleapd_send_grouprestrict_signal_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that requests an action to be run
      that the user is not in a group that is permitted to run, and then
      disconnects before privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        comm_session: pl.PrivleapSession = pl.PrivleapSession(
            PlTestGlobal.test_username
        )
        comm_session.send_msg(
            pl.PrivleapCommClientSignalMsg("test-act-grouprestrict")
        )
        comm_session.close_session()
        part1_passed: bool = False
        part2_passed: bool = False
        if util.compare_privleapd_stderr(
            PlTestData.send_grouprestrict_signal_and_bail_lines_part1,
            quiet=i != 4,
        ):
            part1_passed = True
        # privleapd waits about 3 seconds before sending the UNAUTHORIZED
        # message for security reasons
        time.sleep(3)
        if util.compare_privleapd_stderr(
            PlTestData.unauthorized_broken_pipe_lines, quiet=i != 4
        ):
            part2_passed = True
        if part1_passed and part2_passed:
            return True
    return False


def privleapd_check_signal_response_helper(
    test_action: str,
) -> Tuple[bytes, bytes, int, bool, bool]:
    """
    Test how privleapd handles a comm client that requests a specific action to
      be run. This function actually runs the action, and sends the result back
      to privleapd_check_signal_response_test.
    """

    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    comm_session.send_msg(pl.PrivleapCommClientSignalMsg(test_action))
    accumulated_stdout: bytes = b""
    accumulated_stderr: bytes = b""
    returned_exitcode: int = 0
    returned_unauthorized: bool = False
    error_result: bool = False
    while True:
        try:
            comm_session_msg = comm_session.get_msg()
            if isinstance(
                comm_session_msg, pl.PrivleapCommServerUnauthorizedMsg
            ):
                returned_unauthorized = True
                break
            if isinstance(comm_session_msg, pl.PrivleapCommServerTriggerMsg):
                continue

            if isinstance(
                comm_session_msg, pl.PrivleapCommServerResultStdoutMsg
            ):
                accumulated_stdout += comm_session_msg.stdout_bytes
            elif isinstance(
                comm_session_msg, pl.PrivleapCommServerResultStderrMsg
            ):
                accumulated_stderr += comm_session_msg.stderr_bytes
            elif isinstance(
                comm_session_msg, pl.PrivleapCommServerResultExitcodeMsg
            ):
                returned_exitcode = comm_session_msg.exit_code
                break
            else:
                logging.error(
                    "Unexpected message type '%s' retrieved!",
                    type(comm_session_msg),
                )
                error_result = True
                break
        except Exception:
            logging.error("Failed to retrieve response message!")
            error_result = True
            break
    return (
        accumulated_stdout,
        accumulated_stderr,
        returned_exitcode,
        returned_unauthorized,
        error_result,
    )


def privleapd_check_signal_response_test(test_type: str) -> bool:
    """
    Test how privleapd handles a comm client that requests a specific action to
      be run. General test function usable for basically any signal.
    """

    expect_stdout_data: bytes = b""
    expect_stderr_data: bytes = b""
    expect_exitcode: int = 0
    expect_unauthorized: bool = False
    expect_privleapd_stderr: list[str] = []
    test_action: str | None = None
    match test_type:
        case "test-act-invalid-bash":
            expect_stderr_data = (
                b"/usr/bin/bash: line 1: ahem,: command not " b"found\n"
            )
            expect_exitcode = 127
            expect_privleapd_stderr = PlTestData.send_invalid_bash_signal_lines
            test_action = "test-act-invalid-bash"
        case "test-act-added1-success":
            expect_stdout_data = b"test-act-added1\n"
            expect_privleapd_stderr = PlTestData.test_act_added1_success_lines
            test_action = "test-act-added1"
        case "test-act-added2-success":
            expect_stdout_data = b"test-act-added2\n"
            expect_privleapd_stderr = PlTestData.test_act_added2_success_lines
            test_action = "test-act-added2"
        case "test-act-added1-failure":
            expect_unauthorized = True
            expect_privleapd_stderr = PlTestData.test_act_added1_failure_lines
            test_action = "test-act-added1"
        case "test-act-added2-failure":
            expect_unauthorized = True
            expect_privleapd_stderr = PlTestData.test_act_added2_failure_lines
            test_action = "test-act-added2"
        case "test-act-userpermit":
            expect_stdout_data = b"test-act-userpermit\n"
            expect_privleapd_stderr = (
                PlTestData.test_act_userpermit_success_lines
            )
            test_action = "test-act-userpermit"

    if test_action is None:
        return False
    util.discard_privleapd_stderr()

    accumulated_stdout: bytes
    accumulated_stderr: bytes
    returned_exitcode: int
    returned_unauthorized: bool
    error_result: bool
    (
        accumulated_stdout,
        accumulated_stderr,
        returned_exitcode,
        returned_unauthorized,
        error_result,
    ) = privleapd_check_signal_response_helper(test_action)

    assert_success: bool = True
    if error_result:
        logging.error("Error during signal test!")
        assert_success = False
    if accumulated_stdout != expect_stdout_data:
        logging.error("stdout mismatch!")
        logging.error("Stdout: %s", accumulated_stdout)
        assert_success = False
    if accumulated_stderr != expect_stderr_data:
        logging.error("stderr mismatch!")
        logging.error("Stderr: %s", accumulated_stderr)
        assert_success = False
    if returned_exitcode != expect_exitcode:
        logging.error("Exit code mismatch! Got code %s", returned_exitcode)
        assert_success = False
    if returned_unauthorized != expect_unauthorized:
        logging.error(
            "Unauthorized message mismatch! Got unauthorized: %s",
            returned_unauthorized,
        )
        assert_success = False
    if not util.compare_privleapd_stderr(expect_privleapd_stderr):
        assert_success = False
    return assert_success


def privleapd_send_valid_signal_and_bail_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that requests an action to be run
      that is valid and that the user can run, and then disconnects before
      privleapd can send a reply.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    # This test is prone to race conditions, so we try 5 times and consider it
    # good if one of those times passes.
    for i in range(5):
        comm_session: pl.PrivleapSession = pl.PrivleapSession(
            PlTestGlobal.test_username
        )
        comm_session.send_msg(pl.PrivleapCommClientSignalMsg("test-act-free"))
        comm_session.close_session()
        if util.compare_privleapd_stderr(
            PlTestData.send_valid_signal_and_bail_lines, quiet=i != 4
        ):
            return True
    return False


def privleapd_allowed_action_access_check_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that checks if they are allowed to
      run an action that they are allowed to run.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    comm_session.send_msg(pl.PrivleapCommClientAccessCheckMsg("test-act-free"))
    comm_session_msg: pl.PrivleapMsg = comm_session.get_msg()
    if not isinstance(comm_session_msg, pl.PrivleapCommServerAuthorizedMsg):
        logging.error("Incorrect reply to access check!")
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.allowed_action_access_check_lines
    ):
        assert_success = False
    return assert_success


def privleapd_disallowed_action_access_check_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that checks if they are allowed to
      run an action that they are allowed to run.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    comm_session.send_msg(
        pl.PrivleapCommClientAccessCheckMsg("test-act-userrestrict")
    )
    comm_session_msg: pl.PrivleapMsg = comm_session.get_msg()
    if not isinstance(comm_session_msg, pl.PrivleapCommServerUnauthorizedMsg):
        logging.error("Incorrect reply to access check!")
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.disallowed_action_access_check_lines
    ):
        assert_success = False
    return assert_success


def privleapd_leaprun_terminate_test(bogus: str) -> bool:
    """
    Test how privleapd handles leaprun terminating an action prematurely.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    with subprocess.Popen(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-noreturn",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as leaprun_proc:
        time.sleep(2)
        leaprun_proc.send_signal(signal.SIGINT)
        leaprun_proc.wait()

    if util.compare_privleapd_stderr(PlTestData.leaprun_terminate_lines):
        return True
    return False


def privleapd_terminate_sent_first_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that send a TERMINATE message
      as the first message.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    comm_session.send_msg(pl.PrivleapCommClientTerminateMsg())
    comm_session.close_session()
    if util.compare_privleapd_stderr(PlTestData.terminate_sent_first_lines):
        return True
    return False


def privleapd_invalid_ascii_test(idx_str: str) -> bool:
    """
    Test how privleapd handles a comm client that sends well-formed messages
      with invalid ASCII contents.
    """

    idx: int = int(idx_str)
    if idx > len(PlTestData.invalid_ascii_list):
        return False
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    assert comm_session.backend_socket is not None
    comm_session.backend_socket.send(PlTestData.invalid_ascii_list[idx])
    try:
        # This line will usually error out, we include it only so that we can
        # wait for the server to fully process the invalid data we've sent it.
        _ = comm_session.get_msg()
    except Exception:
        pass
    comm_session.close_session()
    if util.compare_privleapd_stderr(
        PlTestData.invalid_ascii_lines_list[idx], False
    ):
        return True
    return False


def privleapd_send_random_garbage_test(bogus: str) -> bool:
    """
    Test how privleapd handles a comm client that sends pseudorandom data.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    comm_session: pl.PrivleapSession = pl.PrivleapSession(
        PlTestGlobal.test_username
    )
    assert comm_session.backend_socket is not None
    with open("/dev/urandom", "rb") as randfile:
        util.socket_send_raw_bytes(
            comm_session.backend_socket, randfile.read(256)
        )
    comm_session.close_session()
    if util.compare_privleapd_stderr(PlTestData.send_random_garbage_lines):
        return True
    return False


def privleapd_config_reload_test(bogus: str) -> bool:
    """
    Reloads privleapd's configuration, expecting it to succeed.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(pl.PrivleapControlClientReloadMsg())
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    if not isinstance(control_server_msg, pl.PrivleapControlServerOkMsg):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.config_reload_success_lines
    ):
        assert_success = False
    return assert_success


def privleapd_config_reload_fail_test(bogus: str) -> bool:
    """
    Reloads privleapd's configuration, expecting it to fail.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    assert_success: bool = True
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session=True
    )
    control_session.send_msg(pl.PrivleapControlClientReloadMsg())
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    if not isinstance(
        control_server_msg, pl.PrivleapControlServerControlErrorMsg
    ):
        logging.error(
            "privleapd returned unexpected message type: %s",
            type(control_server_msg),
        )
        assert_success = False
    if not util.compare_privleapd_stderr(
        PlTestData.config_reload_failure_lines
    ):
        assert_success = False
    return assert_success


def privleapd_assert_command(
    command_data: list[str],
    exit_code: int,
    stdout_data: bytes = b"",
    stderr_data: bytes = b"",
) -> None:
    """
    Runs a command for leaprun tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global privleapd_asserts_passed
    global privleapd_asserts_failed
    if util.assert_command_result(
        command_data, exit_code, stdout_data, stderr_data
    ):
        logging.info("Assert passed: %s", command_data)
        privleapd_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        privleapd_asserts_failed += 1
        PlTestGlobal.all_asserts_passed = False


def privleapd_assert_function(
    target_function: Callable[[str], bool], func_arg: str, assert_name: str
) -> None:
    """
    Runs a function that returns a boolean, passing the given string argument.
      Records the result as a passed or failed assertion.
    """

    global privleapd_asserts_passed
    global privleapd_asserts_failed
    if target_function(func_arg):
        logging.info("Assert passed: %s", assert_name)
        privleapd_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", assert_name)
        privleapd_asserts_failed += 1
        PlTestGlobal.all_asserts_passed = False


# pylint: disable=too-many-statements
def run_privleapd_tests() -> None:
    """
    Runs all tests on the privleapd executable.
    """

    # ---
    privleapd_assert_function(
        privleapd_check_persistent_users_test,
        "",
        "Ensure all configured persistent users have comm sockets",
    )
    # ---
    privleapd_assert_command(
        ["/usr/bin/privleapd"],
        exit_code=1,
        stderr_data=PlTestData.privleapd_verify_not_running_twice_fail,
    )
    # ---
    util.stop_privleapd_subprocess()
    privleapd_assert_command(
        ["sudo", "-u", PlTestGlobal.test_username, "/usr/bin/privleapd"],
        exit_code=1,
        stderr_data=PlTestData.privleapd_ensure_running_as_root_fail,
    )
    # ---
    privleapd_assert_function(
        write_config_file_with_bad_name,
        "",
        "Write config file that privleapd will ignore",
    )
    util.start_privleapd_subprocess([])
    privleapd_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    privleapd_assert_command(
        [
            "sudo",
            "-u",
            PlTestGlobal.test_username,
            "leaprun",
            "test-act-invalid",
        ],
        exit_code=1,
        stderr_data=PlTestData.test_act_invalid_unauthorized,
    )
    # ---
    util.stop_privleapd_subprocess()
    privleapd_assert_function(
        write_new_config_file,
        "crash_config_file",
        "Write config file with invalid contents",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "bad_config_file",
        "Test privleapd behavior with bad config file",
    )
    # ---
    privleapd_assert_function(
        privleapd_bad_config_file_check_test,
        "",
        "Test privleapd behavior when checking bad config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "crash.conf")),
        "Remove config file with invalid contents",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "duplicate_action_config_file",
        "Write config file with duplicate action name",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "duplicate_action_config_file",
        "Test privleapd behavior with duplicate action config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "duplicate.conf")),
        "Remove config file with duplicate action name",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "wrongorder_config_file",
        "Write config file with badly ordered contents",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "wrongorder_config_file",
        "Test privleapd behavior with badly ordered config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "wrongorder.conf")),
        "Remove config file with badly ordered contents",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "duplicate_keys_config_file",
        "Write config file with duplicate keys",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "duplicate_keys_config_file",
        "Test privleapd behavior with duplicate keys config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "dupkeys.conf")),
        "Remove config file with duplicate keys",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "absent_command_directive_config_file",
        "Write config file with absent command directive",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "absent_command_directive_config_file",
        "Test privleapd behavior with absent command directive config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "absent.conf")),
        "Remove config file with absent command directive",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "invalid_action_config_file",
        "Write config file with invalid action name",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "invalid_action_config_file",
        "Test privleapd behavior with invalid action name config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "invalidaction.conf")),
        "Remove config file with invalid action name",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "unrecognized_header_config_file",
        "Write config file with unrecognized header",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "unrecognized_header_config_file",
        "Test privleapd behavior with unrecognized header config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "unrec_header.conf")),
        "Remove config file with unrecognized header",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "missing_auth_config_file",
        "Write config file with missing auth data",
    )
    privleapd_assert_function(
        privleapd_bad_config_file_test,
        "missing_auth_config_file",
        "Test privleapd behavior with missing auth data config file",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "missing_auth.conf")),
        "Remove config file with missing auth data",
    )
    # ---
    util.start_privleapd_subprocess([])
    privleapd_assert_function(
        privleapd_control_disconnect_test,
        "",
        "Test privleapd client instant disconnect on control socket",
    )
    # ---
    privleapd_assert_function(
        privleapd_create_invalid_user_socket_test,
        "",
        "Test privleapd socket create request for nonexistent user",
    )
    # ---
    privleapd_assert_function(
        privleapd_create_invalid_user_socket_and_bail_test,
        "",
        "Test privleapd socket create request for nonexistent user with "
        "abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_destroy_invalid_user_socket_test,
        "",
        "Test privleapd socket destroy request for nonexistent user",
    )
    # ---
    privleapd_assert_function(
        privleapd_create_user_socket_twice_test,
        "",
        "Test privleapd socket create request for existing user twice",
    )
    # ---
    privleapd_assert_function(
        privleapd_create_existing_user_socket_and_bail_test,
        "",
        "Test privleapd socket create request for user that already has a "
        "socket, with abrupt disconnect",
    )
    # ---
    privleapd_assert_command(
        ["leapctl", "--destroy", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_destroyed,
    )
    privleapd_assert_function(
        make_blocker_socket,
        str(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        ),
        f"Make blocker socket for user {PlTestGlobal.test_username}",
    )
    privleapd_assert_function(
        privleapd_create_blocked_user_socket_test,
        "",
        "Test privleapd socket create request for user with blocked socket",
    )
    # ---
    privleapd_assert_function(
        privleapd_create_blocked_user_socket_and_bail_test,
        "",
        "Test privleapd socket create request for user with blocked socket and "
        "abrupt disconnect",
    )
    privleapd_assert_function(
        try_remove_file,
        str(
            Path(
                PlTestGlobal.privleap_state_dir,
                "comm",
                PlTestGlobal.test_username,
            )
        ),
        f"Remove blocker socket for user {PlTestGlobal.test_username}",
    )
    # ---
    privleapd_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    privleapd_assert_function(
        privleapd_destroy_missing_user_socket_test,
        "",
        "Test privleapd socket destroy request for user with deleted socket",
    )
    # ---
    privleapd_assert_function(
        privleapd_create_expected_disallowed_socket_test,
        "",
        "Test privleapd socket create request for expected disallowed user",
    )
    # ---
    privleapd_assert_function(
        privleapd_destroy_user_socket_and_bail_test,
        "",
        "Test privleapd socket destroy request for existing user, with "
        "abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_destroy_bad_user_socket_and_bail_test,
        "",
        "Test privleapd socket destroy request for existing user with no "
        "socket, with abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_invalid_control_message_test,
        "",
        "Test privleapd against an invalid control message",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_corrupted_control_message_test,
        "",
        "Test privleapd against a corrupted control message",
    )
    # ---
    privleapd_assert_command(
        ["leapctl", "--create", PlTestGlobal.test_username],
        exit_code=0,
        stdout_data=PlTestData.test_username_socket_created,
    )
    privleapd_assert_function(
        privleapd_bail_comm_test,
        "",
        "Test privleapd comm session with abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_invalid_comm_message_test,
        "",
        "Test privleapd against an invalid comm message",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_nonexistent_signal_and_bail_test,
        "",
        "Test privleapd nonexistent action signal with abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_userrestrict_signal_and_bail_test,
        "",
        "Test privleapd userrestrict signal with abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_grouprestrict_signal_and_bail_test,
        "",
        "Test privleapd grouprestrict signal with abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-invalid-bash",
        "Test privleapd's handling of invalid Bash in an action",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_valid_signal_and_bail_test,
        "",
        "Test privleapd valid signal with abrupt disconnect",
    )
    # ---
    privleapd_assert_function(
        privleapd_allowed_action_access_check_test,
        "",
        "Test privleapd access check with allowed action",
    )
    # ---
    privleapd_assert_function(
        privleapd_disallowed_action_access_check_test,
        "",
        "Test privleapd access check with disallowed action",
    )
    # ---
    privleapd_assert_function(
        privleapd_leaprun_terminate_test,
        "",
        "Test privleapd response to leaprun terminate command",
    )
    # ---
    privleapd_assert_function(
        privleapd_terminate_sent_first_test,
        "",
        "Test privleapd response to terminate command being sent first",
    )
    # ---
    privleapd_assert_function(
        privleapd_send_random_garbage_test,
        "",
        "Test privleapd random garbage handling",
    )
    # ---
    for i in range(0, len(PlTestData.invalid_ascii_list)):
        privleapd_assert_function(
            privleapd_invalid_ascii_test,
            str(i),
            f"Test privleapd invalid ASCII handling (iteration {i+1})",
        )
    # ---
    privleapd_assert_command(["/usr/bin/privleapd", "-C"], exit_code=0)
    # ---
    privleapd_assert_command(
        ["/usr/bin/privleapd", "--help"],
        exit_code=0,
        stderr_data=PlTestData.privleapd_help,
    )
    # ---
    privleapd_assert_command(
        ["/usr/bin/privleapd", "-z"],
        exit_code=1,
        stderr_data=PlTestData.privleapd_unrecognized_argument,
    )
    # ---
    privleapd_assert_command(
        ["/usr/bin/privleapd", "\x1b[31mHi\x1b[m"],
        exit_code=1,
        stderr_data=PlTestData.privleapd_unrecognized_argument_escape,
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "added_actions_config_file",
        "Write config file with added actions",
    )
    privleapd_assert_function(
        privleapd_config_reload_test,
        "",
        "Test privleapd restartless config reload, adding actions",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-added1-success",
        "Test privleapd when running a new signal after config reload",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-added2-success",
        "Test privleapd when running another new signal after config reload",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-userpermit",
        "Test privleapd when running old signal after config reload",
    )
    # ---
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "added_actions.conf")),
        "Remove added actions config file",
    )
    privleapd_assert_function(
        privleapd_config_reload_test,
        "",
        "Test privleapd restartless config reload, removing actions",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-added1-failure",
        "Test privleapd when failing to run a new signal after config reload",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-added2-failure",
        "Test privleapd when failing to run another new signal after config"
        + "reload",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-userpermit",
        "Test privleapd when running old signal after config reload",
    )
    # ---
    privleapd_assert_function(
        write_new_config_file,
        "added_actions_bad_config_file",
        "Write bad config file with added actions",
    )
    privleapd_assert_function(
        privleapd_config_reload_fail_test,
        "",
        "Test privleapd restartless config reload, invalid config",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-added1-failure",
        "Test privleapd when failing to run a new signal after config reload",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-added2-failure",
        "Test privleapd when failing to run another new signal after config"
        + "reload",
    )
    # ---
    privleapd_assert_function(
        privleapd_check_signal_response_test,
        "test-act-userpermit",
        "Test privleapd when running old signal after config reload",
    )
    privleapd_assert_function(
        try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "added_actions_bad.conf")),
        "Remove bad added actions config file",
    )
    # ---

    logging.info(
        "privleapd passed asserts: %s, failed asserts: %s",
        privleapd_asserts_passed,
        privleapd_asserts_failed,
    )


def print_test_header() -> None:
    """
    Indicates where in the logs a test started at.
    """

    logging.info(
        """
-------------------------------------
|        BEGIN PRIVLEAP TEST        |
-------------------------------------
"""
    )


def print_result_summary() -> None:
    """
    Prints a summary of the test results via the logging mechanism.
    """

    # pylint: disable=logging-fstring-interpolation
    # Rationale:
    logging.info(
        """
-------------------------------------
|            TEST SUMMARY           |
-------------------------------------

| Component | Asserts | Pass | Fail |
| --------- | ------- | ---- | ---- |
| leapctl   | %7d | %4d | %4d |
| leaprun   | %7d | %4d | %4d |
| privleapd | %7d | %4d | %4d |

-------------------------------------
|         END PRIVLEAP TEST         |
-------------------------------------
""",
        leapctl_asserts_failed + leapctl_asserts_passed,
        leapctl_asserts_passed,
        leapctl_asserts_failed,
        leaprun_asserts_failed + leaprun_asserts_passed,
        leaprun_asserts_passed,
        leaprun_asserts_failed,
        privleapd_asserts_failed + privleapd_asserts_passed,
        privleapd_asserts_passed,
        privleapd_asserts_failed,
    )


def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) >= 2 and sys.argv[1] == "--no-service-handling":
        PlTestGlobal.no_service_handling = True

    logging.basicConfig(
        format="%(funcName)s: %(levelname)s: %(message)s", level=logging.INFO
    )
    print_test_header()
    util.ensure_running_as_root()
    util.stop_privleapd_service()
    util.setup_test_account(
        PlTestGlobal.test_username, PlTestGlobal.test_home_dir
    )
    util.displace_old_privleap_config()
    util.write_privleap_test_config()

    run_leapctl_tests()
    run_leaprun_tests()
    run_privleapd_tests()

    util.restore_old_privleap_config()
    util.stop_privleapd_subprocess()
    util.start_privleapd_service()
    print_result_summary()
    if PlTestGlobal.all_asserts_passed:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
