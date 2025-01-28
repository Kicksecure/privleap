#!/usr/bin/python3 -u

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,global-statement
# Rationale:
#   broad-exception-caught: We use broad exception catching for general-purpose
#     error handlers.
#   global-statement: Only used for the assert count variables, not a problem.

"""
run_test.py - Tests for privleap. This is implemented as an entire program as
  unit testing would not exercise the code sufficiently. This runs through a
  wide variety of real-world-like tests to ensure all components of privleap
  behave as expected.

WARNING: These tests are designed to not damage the system they are ran on, but
  the chances of system damage occurring when running this script is non-zero!
  Please only run this test in a virtual machine with privleap installed.
"""

import os
import sys
import logging
import subprocess
import shutil
import socket
from pathlib import Path
from typing import NoReturn, Tuple, IO
from collections.abc import Callable

import privleap.privleap as pl
import run_test_util as util
from run_test_util import PlTestGlobal, PlTestData

leapctl_asserts_passed: int = 0
leapctl_asserts_failed: int = 0
leaprun_asserts_passed: int = 0
leaprun_asserts_failed: int = 0
privleapd_asserts_passed: int = 0
privleapd_asserts_failed: int = 0

SelectInfo = (Tuple[list[IO[bytes]], list[IO[bytes]], list[IO[bytes]]])

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
    PlTestGlobal.privleap_state_comm_dir.mkdir(parents = True)

def leapctl_assert_command(command_data: list[str], exit_code: int,
    stdout_data: bytes = b"", stderr_data: bytes = b"") -> None:
    """
    Runs a command for leapctl tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global leapctl_asserts_passed
    global leapctl_asserts_failed
    if util.assert_command_result(
        command_data, exit_code, stdout_data, stderr_data):
        logging.info("Assert passed: %s", command_data)
        leapctl_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        leapctl_asserts_failed += 1

def leapctl_assert_function(target_function: Callable[[str], bool],
    func_arg: str, assert_name: str) -> None:
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

def leapctl_server_error_test(bogus: str) -> bool:
    """
    Tests leapctl against a fake server that always errors out regardless of
      the requested action.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    control_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.CONTROL)
    with subprocess.Popen(["leapctl", "--create", PlTestGlobal.test_username],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE) as leapctl_proc:
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
        pl.PrivleapSocketType.CONTROL)
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        with subprocess.Popen(["leapctl", "--create",
            PlTestGlobal.test_username],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE) as leapctl_proc:
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
    util.start_privleapd_subprocess()
    leapctl_assert_command(["leapctl", "--create", "nonexistent"],
                           exit_code = 1,
                           stderr_data = PlTestData.specified_user_missing)
    # ---
    leapctl_assert_command(["leapctl", "--destroy", "nonexistent"],
                           exit_code = 1,
                           stderr_data = PlTestData.specified_user_missing)
    # ---
    leapctl_assert_command(["leapctl", "--create", "_apt"],
                           exit_code = 0,
                           stdout_data = PlTestData.apt_socket_created)
    leapctl_assert_function(test_if_path_exists, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", "_apt")),
        "Ensure _apt socket exists")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", "_apt"],
                           exit_code = 0,
                           stdout_data = PlTestData.apt_socket_destroyed)
    leapctl_assert_function(test_if_path_not_exists,
        str(Path(PlTestGlobal.privleap_state_dir, "comm", "_apt")),
        "Ensure _apt socket does not exist")
    # ---
    leapctl_assert_command(["leapctl", "--create",
        PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_created)
    leapctl_assert_function(test_if_path_exists, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", PlTestGlobal.test_username)),
        "Ensure test user socket exists")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_destroyed)
    leapctl_assert_function(test_if_path_not_exists,
        str(Path(PlTestGlobal.privleap_state_dir, "comm",
            PlTestGlobal.test_username)),
        "Ensure test user socket does not exist")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_missing)
    # ---
    leapctl_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leapctl",
        "--create", PlTestGlobal.test_username],
        exit_code = 1,
        stderr_data = PlTestData.privleapd_connection_failed)
    # ---
    leapctl_assert_command(["leapctl", "--create", PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_created)
    leapctl_assert_command(["leapctl", "--create", PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_exists)
    # ---
    leapctl_assert_function(make_blocker_socket, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", "root")),
        "Create blocker socket for account 'root'")
    leapctl_assert_command(["leapctl", "--create", "root"],
        exit_code = 1,
        stderr_data = PlTestData.root_create_error)
    leapctl_assert_function(try_remove_file, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", "root")),
        "Remove blocker socket for account 'root'")
    # ---
    leapctl_assert_command(["leapctl", "--create", "root"],
        exit_code = 0,
        stdout_data = PlTestData.root_socket_created)
    leapctl_assert_command(["leapctl", "--destroy", "root"],
        exit_code = 0,
        stdout_data = PlTestData.root_socket_destroyed)
    # ---
    leapctl_assert_command(["leapctl", "--create", "root"],
        exit_code = 0,
        stdout_data = PlTestData.root_socket_created)
    leapctl_assert_function(try_remove_file, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", "root")),
        "Remove active socket for account root")
    leapctl_assert_command(["leapctl", "--destroy", "root"],
        exit_code = 0,
        stdout_data = PlTestData.root_socket_destroyed)
    # ---
    util.stop_privleapd_subprocess()
    leapctl_assert_function(leapctl_server_error_test, "",
        "Test leapctl against fake server that always errors out")
    # ---
    leapctl_assert_function(leapctl_server_cutoff_test, "",
        "Test leapctl against fake server that always abruptly disconnects")
    # ---
    leapctl_assert_command(["leapctl"],
        exit_code = 1,
        stdout_data = PlTestData.leapctl_help)
    logging.info("leapctl passed asserts: %s, failed asserts: %s",
        leapctl_asserts_passed, leapctl_asserts_failed)

def leaprun_assert_command(command_data: list[str], exit_code: int,
    stdout_data: bytes = b"", stderr_data: bytes = b"") -> None:
    """
    Runs a command for leaprun tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global leaprun_asserts_passed
    global leaprun_asserts_failed
    if util.assert_command_result(
        command_data, exit_code, stdout_data, stderr_data):
        logging.info("Assert passed: %s", command_data)
        leaprun_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        leaprun_asserts_failed += 1

def leaprun_assert_function(target_function: Callable[[str], bool],
    func_arg: str, assert_name: str) -> None:
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

def leaprun_server_invalid_response_test(bogus: str) -> bool:
    """
    Tests how leapctl handles an invalid message being returned by the server.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.COMMUNICATION,
        user_name = PlTestGlobal.test_username)
    with subprocess.Popen(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-free"],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE) as leaprun_proc:
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
        comm_session._PrivleapSession__send_msg( # type: ignore [attr-defined]
            pl.PrivleapControlServerNouserMsg())
        comm_session.close_session()
        assert comm_socket.backend_socket is not None
        comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        comm_socket.backend_socket.close()
        os.unlink(Path(PlTestGlobal.privleap_state_dir, "comm",
            PlTestGlobal.test_username))
        leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
        if leaprun_result[1] == PlTestData.privleapd_invalid_response:
            return True
    return False

def leaprun_server_cutoff_test(bogus: str) -> bool:
    """
    Tests how leapctl handles the server immediately cutting it off.
    """

    if bogus != "":
        return False
    init_fake_server_dirs()
    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(
        pl.PrivleapSocketType.COMMUNICATION,
        user_name = PlTestGlobal.test_username)
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        with subprocess.Popen(["sudo", "-u", PlTestGlobal.test_username,
            "leaprun", "test-act-free"],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE) as leaprun_proc:
            comm_session = comm_socket.get_session()
            comm_session.close_session()
            assert comm_socket.backend_socket is not None
            leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
            if leaprun_result[1] == PlTestData.privleapd_test_act_free_failed:
                comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
                comm_socket.backend_socket.close()
                os.unlink(Path(PlTestGlobal.privleap_state_dir, "comm",
                    PlTestGlobal.test_username))
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
        user_name = PlTestGlobal.test_username)
    with subprocess.Popen(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-free"],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE) as leaprun_proc:
        comm_session = comm_socket.get_session()
        comm_session.get_msg()
        comm_session.close_session()
        assert comm_socket.backend_socket is not None
        comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        comm_socket.backend_socket.close()
        os.unlink(Path(PlTestGlobal.privleap_state_dir, "comm",
            PlTestGlobal.test_username))
        leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
        if leaprun_result[1] == PlTestData.privleapd_invalid_response:
            return True
    return False

def run_leaprun_tests() -> None:
    """
    Runs all tests on the leaprun executable.
    """

    # ---
    util.start_privleapd_subprocess()
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test"],
        exit_code = 1,
        stderr_data = PlTestData.privleapd_connection_failed)
    # ---
    leaprun_assert_command(["leapctl", "--create", PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_created)
    util.stop_privleapd_subprocess()
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-free"],
        exit_code = 1,
        stderr_data = PlTestData.privleapd_connection_failed)
    # ---
    util.start_privleapd_subprocess()
    leaprun_assert_command(["leapctl", "--create", PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_created)
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-nonexistent"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-nonexistent'.\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-userrestrict"],
        exit_code = 1,
        stderr_data = PlTestData.test_act_nonexistent_unauthorized)
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-grouprestrict"],
        exit_code = 1,
        stderr_data = PlTestData.test_act_grouprestrict_unauthorized)
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-grouppermit-userrestrict"],
        exit_code = 1,
        stderr_data = PlTestData.test_act_grouppermit_userrestrict_unauthorized)
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-grouprestrict-userpermit"],
        exit_code = 1,
        stderr_data = PlTestData.test_act_grouprestrict_userpermit_unauthorized)
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-free"],
        exit_code = 0,
        stdout_data = b"test-act-free\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-userpermit"],
        exit_code = 0,
        stdout_data = b"test-act-userpermit\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-grouppermit"],
        exit_code = 0,
        stdout_data = b"test-act-grouppermit\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-grouppermit-userpermit"],
        exit_code = 0,
        stdout_data = b"test-act-grouppermit-userpermit\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-exit240"],
        exit_code = 240,
        stdout_data = b"test-act-exit240\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-stderr"],
        exit_code = 0,
        stderr_data = b"test-act-stderr\n")
    # ---
    leaprun_assert_command(["sudo", "-u", PlTestGlobal.test_username, "leaprun",
        "test-act-stdout-stderr-interleaved"],
        exit_code = 0,
        stdout_data = b"stdout00\nstdout01\n",
        stderr_data = b"stderr00\nstderr01\n")
    # ---
    util.stop_privleapd_subprocess()
    leaprun_assert_function(leaprun_server_invalid_response_test, "",
        "Leaprun invalid response test")
    # ---
    leaprun_assert_function(leaprun_server_cutoff_test, "",
        "Leaprun server cutoff test")
    # ---
    leaprun_assert_function(leaprun_server_late_cutoff_test, "",
        "Leaprun server late cutoff test")
    logging.info("leaprun passed asserts: %s, failed asserts: %s",
        leaprun_asserts_passed, leaprun_asserts_failed)

def create_lockdown_dir(path_str: str) -> bool:
    """
    Creates a directory with the immutable bit set. Used for confusing
      privleapd.
    """

    try:
        path: Path = Path(path_str)
        path.mkdir(parents = True, exist_ok = True)
        subprocess.run(["chattr", "+i", str(path)], check = True,
            capture_output = True)
        return True
    except Exception:
        return False

def remove_lockdown_on_dir(path_str: str) -> bool:
    """
    Removes the immutable bit from a directory.
    """

    try:
        subprocess.run(["chattr", "-i", path_str], check = True,
            capture_output = True)
        return True
    except Exception:
        return False

def write_config_file_with_bad_name(bogus: str) -> bool:
    """
    Writes a config file with an invalid name. privleapd should ignore this.
    """

    if bogus != "":
        return False
    try:
        with open(Path(PlTestGlobal.privleap_conf_dir, "invalid%config.conf"),
            "w", encoding = "utf-8") as config_file:
            config_file.write(PlTestData.invalid_filename_test_config_file)
        return True
    except Exception:
        return False

def write_bad_config_file(bogus: str) -> bool:
    """
    Writes a config file with invalid contents. This should crash privleapd.
    """

    if bogus != "":
        return False
    try:
        with open(Path(PlTestGlobal.privleap_conf_dir, "crash.conf"), "w",
            encoding = "utf-8") as config_file:
            config_file.write(PlTestData.crash_config_file)
            return True
    except Exception:
        return False

def privleapd_control_disconnect_test(bogus: str) -> bool:
    """
    Tests how privleapd handles a control client that connects and then
      instantly disconnects.
    """

    if bogus != "":
        return False
    util.discard_privleapd_stderr()
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session = True)
    control_session.close_session()
    return util.compare_privleapd_stdout(
        PlTestData.control_disconnect_lines)

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
        is_control_session = True)
    control_session.send_msg(pl.PrivleapControlClientCreateMsg("nonexistent"))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg,
        pl.PrivleapControlServerControlErrorMsg):
        logging.error("privleapd returned unexpected message type: %s",
            type(control_server_msg))
        assert_success = False
    if not util.compare_privleapd_stdout(
        PlTestData.control_create_invalid_user_socket_lines):
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
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session = True)
        control_session.send_msg(pl.PrivleapControlClientCreateMsg(
            "nonexistent"))
        control_session.close_session()
        if util.compare_privleapd_stdout(
            PlTestData.create_invalid_user_socket_and_bail_lines,
            quiet = True):
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
        is_control_session = True)
    control_session.send_msg(pl.PrivleapControlClientDestroyMsg("nonexistent"))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg,
        pl.PrivleapControlServerNouserMsg):
        logging.error("privleapd returned unexpected message type: %s",
            type(control_server_msg))
        assert_success = False
    if not util.compare_privleapd_stdout(
        PlTestData.destroy_invalid_user_socket_lines):
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
        is_control_session = True)
    control_session.send_msg(pl.PrivleapControlClientCreateMsg(
        PlTestGlobal.test_username))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerOkMsg):
        logging.error("privleapd returned unexpected message type: %s",
            type(control_server_msg))
        assert_success = False
    control_session = pl.PrivleapSession(is_control_session = True)
    control_session.send_msg(pl.PrivleapControlClientCreateMsg(
        PlTestGlobal.test_username))
    control_server_msg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerExistsMsg):
        logging.error("privleapd returned unexpected message type: %s",
            type(control_server_msg))
        assert_success = False
    if not util.compare_privleapd_stdout(
        PlTestData.create_user_socket_lines):
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
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session = True)
        control_session.send_msg(pl.PrivleapControlClientCreateMsg(
            PlTestGlobal.test_username))
        control_session.close_session()
        if util.compare_privleapd_stdout(
            PlTestData.create_existing_user_socket_and_bail_lines,
            quiet = True):
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
        is_control_session = True)
    control_session.send_msg(pl.PrivleapControlClientCreateMsg(
        PlTestGlobal.test_username))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg,
        pl.PrivleapControlServerControlErrorMsg):
        logging.error("privleapd returned unexpected message type: %s",
                      type(control_server_msg))
        assert_success = False
    if not util.compare_privleapd_stdout(
        PlTestData.create_blocked_user_socket_lines):
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
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session = True)
        control_session.send_msg(pl.PrivleapControlClientCreateMsg(
            PlTestGlobal.test_username))
        control_session.close_session()
        if util.compare_privleapd_stdout(
            PlTestData.create_blocked_user_socket_and_bail_lines, quiet = True):
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
        os.unlink(Path(PlTestGlobal.privleap_state_dir, "comm",
            PlTestGlobal.test_username))
    except Exception:
        return False
    control_session: pl.PrivleapSession = pl.PrivleapSession(
        is_control_session = True)
    control_session.send_msg(pl.PrivleapControlClientDestroyMsg(
        PlTestGlobal.test_username))
    control_server_msg: pl.PrivleapMsg = control_session.get_msg()
    control_session.close_session()
    if not isinstance(control_server_msg, pl.PrivleapControlServerOkMsg):
        logging.error("privleapd returned unexpected message type: %s",
            type(control_server_msg))
        assert_success = False
    if not util.compare_privleapd_stdout(
        PlTestData.destroy_missing_user_socket_lines):
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
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session = True)
        control_session.send_msg(pl.PrivleapControlClientCreateMsg(
            PlTestGlobal.test_username))
        _ = control_session.get_msg()
        control_session.close_session()
        util.discard_privleapd_stderr()
        control_session = pl.PrivleapSession(
            is_control_session = True)
        control_session.send_msg(pl.PrivleapControlClientDestroyMsg(
            PlTestGlobal.test_username))
        control_session.close_session()
        if util.compare_privleapd_stdout(
            PlTestData.destroy_user_socket_and_bail_lines, quiet = True):
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
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        control_session: pl.PrivleapSession = pl.PrivleapSession(
            is_control_session = True)
        control_session.send_msg(pl.PrivleapControlClientDestroyMsg(
            PlTestGlobal.test_username))
        control_session.close_session()
        if util.compare_privleapd_stdout(
            PlTestData.destroy_bad_user_socket_and_bail_lines):
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
        is_control_session = True)
    assert control_session.backend_socket is not None
    # privleap message packets are simply length-prefixed binary blobs, with the
    # length specified as a 4-byte big-endian integer.
    util.socket_send_raw_bytes(control_session.backend_socket,
        b"\x00\x00\x00\x0DBOB asdfghjkl")
    control_session.close_session()
    if not util.compare_privleapd_stdout(
        PlTestData.send_invalid_control_message_lines):
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
        is_control_session = True)
    assert control_session.backend_socket is not None
    # CREATE is only supposed to have a single parameter after it, the name of
    # the user to create a socket for. The "exploit" at the end is additional
    # data that isn't expected and should be rejected. The pun in "root exploit"
    # was not originally intended, but was too good to leave out :)
    util.socket_send_raw_bytes(control_session.backend_socket,
        b"\x00\x00\x00\x13CREATE root exploit")
    control_session.close_session()
    if not util.compare_privleapd_stdout(
        PlTestData.send_corrupted_control_message_lines):
        return False
    return True

def privleapd_assert_function(target_function: Callable[[str], bool],
                              func_arg: str, assert_name: str) -> None:
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

def privleapd_assert_command(command_data: list[str], exit_code: int,
    stdout_data: bytes = b"", stderr_data: bytes = b"") -> None:
    """
    Runs a command for leaprun tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global privleapd_asserts_passed
    global privleapd_asserts_failed
    if util.assert_command_result(
            command_data, exit_code, stdout_data, stderr_data):
        logging.info("Assert passed: %s", command_data)
        privleapd_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        privleapd_asserts_failed += 1

def run_privleapd_tests() -> None:
    """
    Runs all tests on the privleapd executable.
    """

    # ---
    util.start_privleapd_subprocess()
    privleapd_assert_command(["/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data = PlTestData.privleapd_verify_not_running_twice_fail)
    # ---
    util.stop_privleapd_subprocess()
    privleapd_assert_command(["sudo", "-u", PlTestGlobal.test_username,
        "/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data = PlTestData.privleapd_ensure_running_as_root_fail)
    # ---
    privleapd_assert_function(create_lockdown_dir,
        str(PlTestGlobal.privleap_state_dir),
        "Create immutable privleapd state directory")
    privleapd_assert_command(["/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data = PlTestData.could_not_delete_run_privleapd)
    privleapd_assert_function(remove_lockdown_on_dir,
        str(PlTestGlobal.privleap_state_dir),
        "Remove immutable bit from privleapd state directory")
    # ---
    privleapd_assert_function(write_config_file_with_bad_name, "",
        "Write config file that privleapd will ignore")
    util.start_privleapd_subprocess()
    privleapd_assert_command(["leapctl", "--create",
        PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_created)
    privleapd_assert_command(["sudo", "-u", PlTestGlobal.test_username,
        "leaprun", "test-act-invalid"],
        exit_code = 1,
        stderr_data = PlTestData.test_act_invalid_unauthorized)
    # ---
    util.stop_privleapd_subprocess()
    privleapd_assert_function(write_bad_config_file, "",
        "Write config file with invalid contents")
    privleapd_assert_command(["/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data = PlTestData.privleapd_config_file_parse_fail)
    privleapd_assert_function(try_remove_file,
        str(Path(PlTestGlobal.privleap_conf_dir, "crash.conf")),
        "Remove config file with invalid contents")
    # ---
    util.start_privleapd_subprocess()
    privleapd_assert_function(privleapd_control_disconnect_test, "",
        "Test privleapd client instant disconnect on control socket")
    # ---
    privleapd_assert_function(privleapd_create_invalid_user_socket_test,
        "", "Test privleapd socket create request for nonexistent user")
    # ---
    privleapd_assert_function(
        privleapd_create_invalid_user_socket_and_bail_test, "",
        "Test privleapd socket create request for nonexistent user with "
            "abrupt disconnect")
    # ---
    privleapd_assert_function(privleapd_destroy_invalid_user_socket_test,
        "", "Test privleapd socket destroy request for nonexistent user")
    # ---
    privleapd_assert_function(privleapd_create_user_socket_twice_test,
        "", "Test privleapd socket create request for existing user twice")
    # ---
    privleapd_assert_function(
        privleapd_create_existing_user_socket_and_bail_test, "",
        "Test privleapd socket create request for user that already has a "
            "socket, with abrupt disconnect")
    # ---
    privleapd_assert_command(["leapctl", "--destroy",
        PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_destroyed)
    privleapd_assert_function(make_blocker_socket, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", PlTestGlobal.test_username)),
        f"Make blocker socket for user {PlTestGlobal.test_username}")
    privleapd_assert_function(privleapd_create_blocked_user_socket_test,
        "", "Test privleapd socket create request for user with blocked socket")
    # ---
    privleapd_assert_function(
        privleapd_create_blocked_user_socket_and_bail_test, "",
        "Test privleapd socket create request for user with blocked socket and"
            "abrupt disconnect")
    privleapd_assert_function(try_remove_file, str(Path(
        PlTestGlobal.privleap_state_dir, "comm", PlTestGlobal.test_username)),
        f"Remove blocker socket for user {PlTestGlobal.test_username}")
    # ---
    privleapd_assert_command(["leapctl", "--create",
        PlTestGlobal.test_username],
        exit_code = 0,
        stdout_data = PlTestData.test_username_socket_created)
    privleapd_assert_function(privleapd_destroy_missing_user_socket_test,
        "", "Test privleapd socket destroy request for user with deleted "
            "socket")
    # ---
    privleapd_assert_function(privleapd_destroy_user_socket_and_bail_test,
        "", "Test privleapd socket destroy request for existing user, with "
            "abrupt disconnect")
    # ---
    privleapd_assert_function(privleapd_destroy_bad_user_socket_and_bail_test,
        "", "Test privleapd socket destroy request for existing user with no "
            "socket, with abrupt disconnect")
    # ---
    privleapd_assert_function(privleapd_send_invalid_control_message_test,
        "", "Test privleapd against an invalid control message")
    # ---
    privleapd_assert_function(privleapd_send_corrupted_control_message_test,
        "", "Test privleapd against a corrupted control message")
    logging.info("privleapd passed asserts: %s, failed asserts: %s",
        privleapd_asserts_passed, privleapd_asserts_failed)

def main() -> NoReturn:
    """
    Main function.
    """

    logging.basicConfig(format = "%(funcName)s: %(levelname)s: %(message)s",
        level = logging.INFO)
    util.ensure_running_as_root()
    util.stop_privleapd_service()
    util.setup_test_account(PlTestGlobal.test_username,
        PlTestGlobal.test_home_dir)
    util.displace_old_privleap_config()
    util.write_privleap_test_config()

    run_leapctl_tests()
    run_leaprun_tests()
    run_privleapd_tests()

    util.restore_old_privleap_config()
    util.stop_privleapd_subprocess()
    util.start_privleapd_service()
    sys.exit(0)

if __name__ == "__main__":
    main()
