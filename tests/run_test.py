#!/usr/bin/python3 -u

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,global-statement
# Rationale:
#   broad-exception-caught: We use broad exception catching for general-purpose
#     error handlers.
#   global-statement: Dealing with global variables in a dedicated class was
#     getting very cumbersome for this script. pylint discourages the usage, of
#     the global statement, but this is a good use case for it.

"""
run_test.py - Unit tests for privleap. This is implemented as an entire program
  as traditional unit testing would not exercise the code sufficiently. This
  runs through a wide variety of real-world-like tests to ensure all components
  of privleap behave as expected.

WARNING: These tests are designed to not damage the system they are ran on, but
  the chances of system damage occurring when running this script is non-zero!
  Please only run this test in a virtual machine with privleap installed.
"""

import os
import sys
import pwd
import grp
import logging
import subprocess
import shutil
import select
import socket
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import NoReturn, Tuple, IO
from collections.abc import Callable

import privleap.privleap as pl

test_username: str = "privleaptest"
test_username_bytes: bytes = test_username.encode("utf-8")
test_home_dir: Path = Path(f"/home/{test_username}")
privleap_conf_base_dir: Path = Path("/etc/privleap")
privleap_conf_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d")
privleap_conf_backup_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d.bak")
privleap_state_dir: Path = Path("/run/privleapd")
privleap_state_comm_dir: Path = Path(privleap_state_dir, "comm")
privleapd_proc: subprocess.Popen[str] | None = None
linebuf: str = ""
leapctl_asserts_passed: int = 0
leapctl_asserts_failed: int = 0
leaprun_asserts_passed: int = 0
leaprun_asserts_failed: int = 0
privleapd_asserts_passed: int = 0
privleapd_asserts_failed: int = 0
SelectInfo = (Tuple[list[IO[bytes]], list[IO[bytes]], list[IO[bytes]]])

def proc_try_readline(proc: subprocess.Popen[str], timeout: int) -> str | None:
    """
    Reads a line of test from the stdout of a process. Allows specifying a
      timeout for bailing out early. Uses select.select() in the background, but
      should be immune to issues like select.select() returning before a newline
      is present.
    """

    global linebuf
    assert proc.stdout is not None
    current_time: datetime = datetime.now()
    end_time = current_time + timedelta(seconds = timeout)
    while True:
        current_time = datetime.now()
        ready_streams: SelectInfo = select.select([proc.stdout], [], [],
            (end_time - current_time).seconds)
        if len(ready_streams[0]) == 0:
            return None
        linebuf += proc.stdout.read()
        linebuf_parts: list[str] = linebuf.split("\n", maxsplit = 1)
        if len(linebuf_parts) == 2:
            linebuf = linebuf_parts[1]
            return linebuf_parts[0]
        if current_time > end_time:
            return None

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

def ensure_running_as_root() -> None:
    """
    Ensures the test is running as root. The tests cannot function when
      running as a user as they have to execute commands as root.
    """

    if os.geteuid() != 0:
        logging.error("The tests must run as root.")
        sys.exit(1)

def setup_test_account() -> None:
    """
    Ensures the user account used by the test script exists and is properly
      configured.
    """

    user_name_list: list[str] = [p.pw_name for p in pwd.getpwall()]
    if test_username not in user_name_list:
        try:
            subprocess.run(["useradd", "-m", test_username],
                check = True)
        except Exception as e:
            logging.critical("Could not create user '%s'!",
                test_username, exc_info = e)
            sys.exit(1)
    user_gid: int = pwd.getpwnam(test_username).pw_gid
    group_list: list[str] = [grp.getgrgid(gid).gr_name \
        for gid in os.getgrouplist(test_username, user_gid)]
    if not "sudo" in group_list:
        try:
            subprocess.run(["adduser", test_username, "sudo"],
                check = True)
        except Exception as e:
            logging.critical("Could not add user '%s' to group 'sudo'!",
                test_username, exc_info = e)
            sys.exit(1)
    ensure_path_lacks_files(test_home_dir)
    if not test_home_dir.exists():
        test_home_dir.mkdir(parents = True)
        shutil.chown(test_home_dir, user = test_username, group = test_username)

def ensure_path_lacks_files(path: Path) -> None:
    """
    Ensures all components of the provided path either do not exist or are
      directories.
    """

    if path.exists() and not path.is_dir():
        logging.critical("Path '%s' contains a non-dir at '%s'!", str(path),
            str(path))
        sys.exit(1)
    for parent_path in path.parents:
        if parent_path.exists() and not parent_path.is_dir():
            logging.critical("Path '%s' contains a non-dir at '%s'!", str(path),
                str(parent_path))
            sys.exit(1)

def displace_old_privleap_config() -> None:
    """
    Moves the existing privleap configuration dir to a backup location so we can
      put custom config in for testing purposes.
    """

    if privleap_conf_backup_dir.exists():
        logging.critical("Backup config dir at '%s' exist, please move or "
            "remove it before continuing.", str(privleap_conf_backup_dir))
        sys.exit(1)
    ensure_path_lacks_files(privleap_conf_dir)
    ensure_path_lacks_files(privleap_conf_backup_dir)
    privleap_conf_base_dir.mkdir(parents = True, exist_ok = True)
    if privleap_conf_dir.exists():
        shutil.move(privleap_conf_dir, privleap_conf_backup_dir)
    privleap_conf_dir.mkdir(parents = True, exist_ok = True)

def restore_old_privleap_config() -> None:
    """
    Moves the backup privleap configuration dir back to the original location.
    """

    ensure_path_lacks_files(privleap_conf_dir)
    ensure_path_lacks_files(privleap_conf_backup_dir)
    privleap_conf_base_dir.mkdir(parents = True, exist_ok = True)
    if privleap_conf_backup_dir.exists():
        if privleap_conf_dir.exists():
            shutil.rmtree(privleap_conf_dir)
        shutil.move(privleap_conf_backup_dir, privleap_conf_dir)
    # Make sure the "real" config dir exists even if there wasn't a backup dir
    # to move into position
    privleap_conf_dir.mkdir(parents = True, exist_ok = True)

def start_privleapd_subprocess() -> None:
    """
    Launches privleapd as a subprocess so its output can be monitored by the
      tester.
    """

    global privleapd_proc

    try:
        subprocess.run(["systemctl", "stop", "privleapd"], check = True)
    except Exception as e:
        logging.critical("Could not stop privleapd service!",
            exc_info = e)
        sys.exit(1)
    try:
        # pylint: disable=consider-using-with
        # Rationale:
        #   consider-using-with: "with" is not suitable for the architecture of
        #   this script in this scenario.
        privleapd_proc = subprocess.Popen(["/usr/bin/privleapd"],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            encoding = "utf-8")
    except Exception as e:
        logging.critical("Could not start privleapd server!",
            exc_info = e)
    assert privleapd_proc is not None
    time.sleep(1)
    early_privleapd_output: str | None = proc_try_readline(privleapd_proc, 1)
    if early_privleapd_output is not None:
        logging.critical("privleapd returned error messages at startup!")
        while True:
            logging.critical(early_privleapd_output)
            early_privleapd_output = proc_try_readline(privleapd_proc, 1)
            if early_privleapd_output is None:
                break
        sys.exit(1)

def stop_privleapd_subprocess() -> None:
    """
    Stops the privleapd subprocess.
    """

    assert privleapd_proc is not None
    try:
        privleapd_proc.kill()
        _ = privleapd_proc.communicate()
    except Exception as e:
        logging.critical("Could not kill privleapd!", exc_info = e)
    time.sleep(1)

def assert_command_result(command_data: list[str], exit_code: int,
    stdout_data: bytes = b"", stderr_data: bytes = b"") -> bool:
    """
    Runs a command and ensures that the stdout, stderr, and exitcode match
      expected values.
    """

    test_result: subprocess.CompletedProcess[bytes] \
        = subprocess.run(command_data, check = False, capture_output = True)
    logging.info("Ran command: %s", command_data)
    logging.info("Exit code: %s", test_result.returncode)
    logging.info("Stdout: %s", test_result.stdout)
    logging.info("Stderr: %s", test_result.stderr)
    assert_failed: bool = False
    if exit_code != test_result.returncode:
        logging.error("Exit code assert failed, expected: %s", exit_code)
        assert_failed = True
    if stdout_data != test_result.stdout:
        logging.error("Stdout assert failed, expected: %s", stdout_data)
        assert_failed = True
    if stderr_data != test_result.stderr:
        logging.error("Stderr assert failed, expected: %s", stderr_data)
        assert_failed = True
    if assert_failed:
        return False
    return True

def leapctl_assert_command(command_data: list[str], exit_code: int,
    stdout_data: bytes = b"", stderr_data: bytes = b"") -> None:
    """
    Runs a command for leapctl tests, testing the output against expected values
      and recording the result as a passed or failed assertion.
    """

    global leapctl_asserts_passed
    global leapctl_asserts_failed
    if assert_command_result(command_data, exit_code, stdout_data, stderr_data):
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

    if privleap_state_dir.exists():
        shutil.rmtree(privleap_state_dir)
    privleap_state_comm_dir.mkdir(parents = True)

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
    with subprocess.Popen(["leapctl", "--create", test_username],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE) as leapctl_proc:
        control_session = control_socket.get_session()
        control_session.get_msg()
        control_session.send_msg(pl.PrivleapControlServerControlErrorMsg())
        control_session.close_session()
        assert control_socket.backend_socket is not None
        control_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        control_socket.backend_socket.close()
        os.unlink(Path(privleap_state_dir, "control"))
        leapctl_result: Tuple[bytes, bytes] = leapctl_proc.communicate()
        if leapctl_result[1] == (b"ERROR: privleapd encountered an error while "
            + b"creating a comm socket for user '"
            + test_username_bytes
            + b"'!\n"):
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
        with subprocess.Popen(["leapctl", "--create", test_username],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE) as leapctl_proc:
            control_session = control_socket.get_session()
            control_session.close_session()
            assert control_socket.backend_socket is not None
            leapctl_result: Tuple[bytes, bytes] = leapctl_proc.communicate()
            if leapctl_result[1] == (b"ERROR: privleapd didn't return a valid "
                + b"response!\n"):
                control_socket.backend_socket.shutdown(socket.SHUT_RDWR)
                control_socket.backend_socket.close()
                os.unlink(Path(privleap_state_dir, "control"))
                return True
    return False

def run_leapctl_tests() -> None:
    """
    Runs all tests on the leapctl executable.
    """

    # ---
    start_privleapd_subprocess()
    leapctl_assert_command(["leapctl", "--create", "nonexistent"],
        exit_code = 1,
        stderr_data = b"ERROR: Specified user does not exist.\n")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", "nonexistent"],
        exit_code = 1,
        stderr_data = b"ERROR: Specified user does not exist.\n")
    # ---
    leapctl_assert_command(["leapctl", "--create", "_apt"],
        exit_code = 0,
        stdout_data = b"Comm socket created for user '_apt'.\n")
    leapctl_assert_function(test_if_path_exists, str(Path(privleap_state_dir,
        "comm", "_apt")), "Ensure _apt socket exists")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", "_apt"],
        exit_code = 0,
        stdout_data = b"Comm socket destroyed for user '_apt'.\n")
    leapctl_assert_function(test_if_path_not_exists,
        str(Path(privleap_state_dir, "comm", "_apt")),
        "Ensure _apt socket does not exist")
    # ---
    leapctl_assert_command(["leapctl", "--create", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket created for user '"
            + test_username_bytes
            + b"'.\n")
    leapctl_assert_function(test_if_path_exists, str(Path(privleap_state_dir,
        "comm", test_username)), "Ensure test user socket exists")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket destroyed for user '"
            + test_username_bytes
            + b"'.\n")
    leapctl_assert_function(test_if_path_not_exists,
        str(Path(privleap_state_dir, "comm", test_username)),
        "Ensure test user socket does not exist")
    # ---
    leapctl_assert_command(["leapctl", "--destroy", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket does not exist for user '"
            + test_username_bytes
            + b"'.\n")
    # ---
    leapctl_assert_command(["sudo", "-u", test_username, "leapctl",
        "--create", test_username],
        exit_code = 1,
        stderr_data = b"ERROR: Could not connect to privleapd!\n")
    # ---
    leapctl_assert_command(["leapctl", "--create", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket created for user '"
            + test_username_bytes
            + b"'.\n")
    leapctl_assert_command(["leapctl", "--create", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket already exists for user '"
            + test_username_bytes
            + b"'.\n")
    # ---
    leapctl_assert_function(make_blocker_socket, str(Path(privleap_state_dir,
        "comm", "root")), "Create blocker socket for account 'root'")
    leapctl_assert_command(["leapctl", "--create", "root"],
        exit_code = 1,
        stderr_data=b"ERROR: privleapd encountered an error while creating a "
            + b"comm socket for user 'root'!\n")
    leapctl_assert_function(try_remove_file, str(Path(privleap_state_dir,
        "comm", "root")), "Remove blocker socket for account 'root'")
    # ---
    leapctl_assert_command(["leapctl", "--create", "root"],
        exit_code = 0,
        stdout_data = b"Comm socket created for user 'root'.\n")
    leapctl_assert_command(["leapctl", "--destroy", "root"],
        exit_code = 0,
        stdout_data = b"Comm socket destroyed for user 'root'.\n")
    # ---
    leapctl_assert_command(["leapctl", "--create", "root"],
        exit_code = 0,
        stdout_data = b"Comm socket created for user 'root'.\n")
    leapctl_assert_function(try_remove_file, str(Path(privleap_state_dir,
        "comm", "root")), "Remove active socket for account root")
    leapctl_assert_command(["leapctl", "--destroy", "root"],
        exit_code = 0,
        stdout_data = b"Comm socket destroyed for user 'root'.\n")
    # ---
    stop_privleapd_subprocess()
    leapctl_assert_function(leapctl_server_error_test, "",
        "Test leapctl against fake server that always errors out")
    # ---
    leapctl_assert_function(leapctl_server_cutoff_test, "",
        "Test leapctl against fake server that always abruptly disconnects")
    # ---
    leapctl_assert_command(["leapctl"],
        exit_code = 1,
        stdout_data \
= b"leapctl <--create|--destroy> <user>\n"
+ b"\n"
+ b"    user : The username or UID of the user account to create or destroy a\n"
+ b"           communication socket for.\n"
+ b"    --create : Specifies that leapctl should request a communication socket to\n"
+ b"               be created for the specified user.\n"
+ b"    --destroy : Specifies that leapctl should request a communication socket\n"
+ b"                to be destroyed for the specified user.\n")
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
    if assert_command_result(command_data, exit_code, stdout_data, stderr_data):
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
        pl.PrivleapSocketType.COMMUNICATION, user_name = test_username)
    with subprocess.Popen(["sudo", "-u", test_username, "leaprun",
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
        os.unlink(Path(privleap_state_dir, "comm", test_username))
        leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
        if leaprun_result[1] == (b"ERROR: privleapd didn't return a valid "
            + b"response!\n"):
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
        pl.PrivleapSocketType.COMMUNICATION, user_name = test_username)
    # This test is prone to race conditions, so we try 20 times and consider it
    # good if one of those times passes.
    for _ in range(20):
        with subprocess.Popen(["sudo", "-u", test_username, "leaprun",
            "test-act-free"],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE) as leaprun_proc:
            comm_session = comm_socket.get_session()
            comm_session.close_session()
            assert comm_socket.backend_socket is not None
            leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
            if leaprun_result[1] == (b"ERROR: Could not request privleapd to "
                + b"run action 'test-act-free'!\n"):
                comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
                comm_socket.backend_socket.close()
                os.unlink(Path(privleap_state_dir, "comm", test_username))
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
        pl.PrivleapSocketType.COMMUNICATION, user_name = test_username)
    with subprocess.Popen(["sudo", "-u", test_username, "leaprun",
        "test-act-free"],
        stdout = subprocess.PIPE,
        stderr = subprocess.PIPE) as leaprun_proc:
        comm_session = comm_socket.get_session()
        comm_session.get_msg()
        comm_session.close_session()
        assert comm_socket.backend_socket is not None
        comm_socket.backend_socket.shutdown(socket.SHUT_RDWR)
        comm_socket.backend_socket.close()
        os.unlink(Path(privleap_state_dir, "comm", test_username))
        leaprun_result: Tuple[bytes, bytes] = leaprun_proc.communicate()
        if leaprun_result[1] == (b"ERROR: privleapd didn't return a valid "
            + b"response!\n"):
            return True
    return False

def write_leaprun_test_config() -> None:
    """
    Writes test privleap config data.
    """

    with open(Path(privleap_conf_dir, "unit-test.conf"), "w",
        encoding = "utf-8") as config_file:
        config_file.write(f"""[test-act-free]
Command=echo 'test-act-free'

[test-act-userrestrict]
Command=echo 'test-act-userrestrict'
AuthorizedUser=sys

[test-act-grouprestrict]
Command=echo 'test-act-grouprestrict'
AuthorizedGroup=sys

[test-act-grouppermit-userrestrict]
Command=echo 'test-act-grouppermit-userrestrict'
AuthorizedUser=sys
AuthorizedGroup={test_username}

[test-act-grouprestrict-userpermit]
Command=echo 'test-act-grouprestrict-userpermit'
AuthorizedUser={test_username}
AuthorizedGroup=sys

[test-act-userpermit]
Command=echo 'test-act-userpermit'
AuthorizedUser={test_username}

[test-act-grouppermit]
Command=echo 'test-act-grouppermit'
AuthorizedGroup={test_username}

[test-act-grouppermit-userpermit]
Command=echo 'test-act-grouppermit-userpermit'
AuthorizedUser={test_username}
AuthorizedGroup={test_username}

[test-act-exit240]
Command=echo 'test-act-exit240'; exit 240

[test-act-stderr]
Command=1>&2 echo 'test-act-stderr'

[test-act-stdout-stderr-interleaved]
Command=echo 'stdout00'; 1>&2 echo 'stderr00'; echo 'stdout01'; 1>&2 echo 'stderr01'
""")

def run_leaprun_tests() -> None:
    """
    Runs all tests on the leaprun executable.
    """

    # ---
    start_privleapd_subprocess()
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun", "test"],
        exit_code = 1,
        stderr_data = b"ERROR: Could not connect to privleapd!\n")
    # ---
    leaprun_assert_command(["leapctl", "--create", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket created for user '"
            + test_username_bytes
            + b"'.\n")
    stop_privleapd_subprocess()
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-free"],
        exit_code = 1,
        stderr_data = b"ERROR: Could not connect to privleapd!\n")
    # ---
    start_privleapd_subprocess()
    leaprun_assert_command(["leapctl", "--create", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket created for user '"
            + test_username_bytes
            + b"'.\n")
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-nonexistent"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-nonexistent'.\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-userrestrict"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-userrestrict'.\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-grouprestrict"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-grouprestrict'.\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-grouppermit-userrestrict"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-grouppermit-userrestrict'.\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-grouprestrict-userpermit"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-grouprestrict-userpermit'.\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-free"],
        exit_code = 0,
        stdout_data = b"test-act-free\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-userpermit"],
        exit_code = 0,
        stdout_data = b"test-act-userpermit\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-grouppermit"],
        exit_code = 0,
        stdout_data = b"test-act-grouppermit\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-grouppermit-userpermit"],
        exit_code = 0,
        stdout_data = b"test-act-grouppermit-userpermit\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-exit240"],
        exit_code = 240,
        stdout_data = b"test-act-exit240\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-stderr"],
        exit_code = 0,
        stderr_data = b"test-act-stderr\n")
    # ---
    leaprun_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-stdout-stderr-interleaved"],
        exit_code = 0,
        stdout_data = b"stdout00\nstdout01\n",
        stderr_data = b"stderr00\nstderr01\n")
    # ---
    stop_privleapd_subprocess()
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
    if assert_command_result(command_data, exit_code, stdout_data, stderr_data):
        logging.info("Assert passed: %s", command_data)
        privleapd_asserts_passed += 1
    else:
        logging.error("Assert failed: %s", command_data)
        privleapd_asserts_failed += 1

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
        with open(Path(privleap_conf_dir, "invalid%config.conf"), "w",
            encoding = "utf-8") as config_file:
            config_file.write("""[test-act-invalid]
Command=echo 'test-act-invalid'
""")
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
        with open(Path(privleap_conf_dir, "crash.conf"), "w",
            encoding = "utf-8") as config_file:
            # noinspection SpellCheckingInspection
            config_file.write("""[test-act-crash]
Commandecho 'test-act-crash'
""")
            return True
    except Exception:
        return False

def run_privleapd_tests() -> None:
    """
    Runs all tests on the privleapd executable.
    """

    # ---
    start_privleapd_subprocess()
    privleapd_assert_command(["/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data = b"verify_not_running_twice: CRITICAL: Cannot run two "
            + b"privleapd processes at the same time!\n")
    # ---
    stop_privleapd_subprocess()
    privleapd_assert_command(["sudo", "-u", test_username,
        "/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data = b"ensure_running_as_root: CRITICAL: privleapd must run "
            + b"as root!\n")
    # ---
    privleapd_assert_function(create_lockdown_dir, str(privleap_state_dir),
        "Create immutable privleapd state directory")
    privleapd_assert_command(["/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data
= b"cleanup_old_state_dir: CRITICAL: Could not delete '/run/privleapd'!\n"
+ b"Traceback (most recent call last):\n"
+ b"  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line 448, "
+ b"in cleanup_old_state_dir\n"
+ b"    shutil.rmtree(pl.PrivleapCommon.state_dir)\n"
+ b"  File \"/usr/lib/python3.11/shutil.py\", line 732, in rmtree\n"
+ b"    _rmtree_safe_fd(fd, path, onerror)\n"
+ b"  File \"/usr/lib/python3.11/shutil.py\", line 683, in _rmtree_safe_fd\n"
+ b"    onerror(os.unlink, fullname, sys.exc_info())\n"
+ b"  File \"/usr/lib/python3.11/shutil.py\", line 681, in _rmtree_safe_fd\n"
+ b"    os.unlink(entry.name, dir_fd=topfd)\n"
+ b"PermissionError: [Errno 1] Operation not permitted: 'control'\n")
    privleapd_assert_function(remove_lockdown_on_dir, str(privleap_state_dir),
        "Remove immutable bit from privleapd state directory")
    # ---
    privleapd_assert_function(write_config_file_with_bad_name, "",
        "Write config file that privleapd will ignore")
    start_privleapd_subprocess()
    privleapd_assert_command(["leapctl", "--create", test_username],
        exit_code = 0,
        stdout_data = b"Comm socket created for user '"
            + test_username_bytes
            + b"'.\n")
    privleapd_assert_command(["sudo", "-u", test_username, "leaprun",
        "test-act-invalid"],
        exit_code = 1,
        stderr_data = b"ERROR: You are unauthorized to run action "
            + b"'test-act-invalid'.\n")
    # ---
    stop_privleapd_subprocess()
    privleapd_assert_function(write_bad_config_file, "",
        "Write config file with invalid contents")
    # noinspection SpellCheckingInspection
    privleapd_assert_command(["/usr/bin/privleapd"],
        exit_code = 1,
        stderr_data
= b"parse_config_files: CRITICAL: Failed to parse config file "
+ b"'/etc/privleap/conf.d/crash.conf'!\n"
+ b"Traceback (most recent call last):\n"
+ b"  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line 470, "
+ b"in parse_config_files\n"
+ b"    = pl.PrivleapCommon.parse_config_file(f.read())\n"
+ b"      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
+ b"  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line 968, "
+ b"in parse_config_file\n"
+ b"    raise ValueError(\"Invalid config line '\" + line +\"'\")\n"
+ b"ValueError: Invalid config line 'Commandecho 'test-act-crash''\n")

def main() -> NoReturn:
    """
    Main function.
    """

    logging.basicConfig(format = "%(funcName)s: %(levelname)s: %(message)s",
        level = logging.INFO)
    ensure_running_as_root()
    setup_test_account()
    displace_old_privleap_config()
    write_leaprun_test_config()

    run_leapctl_tests()
    run_leaprun_tests()
    run_privleapd_tests()

    restore_old_privleap_config()
    sys.exit(0)

if __name__ == "__main__":
    main()
