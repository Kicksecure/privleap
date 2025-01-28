#!/usr/bin/python3 -u

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught,too-few-public-methods
# Rationale:
#   broad-exception-caught: We use broad exception catching for general-purpose
#     error handlers.
#   too-few-public-methods: Global variable class uses no methods intentionally.

"""
run_test_util.py - Utility functions for run_test.py.
"""

import select
import subprocess
import os
import sys
import logging
import pwd
import grp
import shutil
import time
import socket
import fcntl
from pathlib import Path
from typing import Tuple, IO
from datetime import datetime, timedelta

class PlTestGlobal:
    """
    Global variables for privleap tests.
    """

    linebuf: str = ""
    privleap_conf_base_dir: Path = Path("/etc/privleap")
    privleap_conf_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d")
    privleap_conf_backup_dir: Path = Path(f"{privleap_conf_base_dir}/conf.d.bak")
    privleapd_proc: subprocess.Popen[str] | None = None
    test_username: str = "privleaptest"
    test_username_bytes: bytes = test_username.encode("utf-8")
    test_home_dir: Path = Path(f"/home/{test_username}")
    privleap_state_dir: Path = Path("/run/privleapd")
    privleap_state_comm_dir: Path = Path(privleap_state_dir, "comm")
    readline_timeout: float = 1
    privleapd_running: bool = False

SelectInfo = (Tuple[list[IO[bytes]], list[IO[bytes]], list[IO[bytes]]])

def proc_try_readline(proc: subprocess.Popen[str], timeout: float,
    read_stderr: bool = False) -> str | None:
    """
    Reads a line of test from the stdout or stderr of a process. Allows
      specifying a timeout for bailing out early. The stdout (or stderr)
      of the process must be in non-blocking mode.
    """

    # TODO: This function is just a disaster from a readability standpoint.
    #   Trying to avoid deadlocks, unnecessary delays, and incorrect returns of
    #   None was not easy, but surely there's a better way to write it than
    #   this.

    assert proc.stdout is not None
    assert proc.stderr is not None
    if "\n" in PlTestGlobal.linebuf:
        linebuf_parts: list[str] = PlTestGlobal.linebuf.split("\n",
            maxsplit = 1)
        PlTestGlobal.linebuf = linebuf_parts[1]
        return linebuf_parts[0] + "\n"
    if read_stderr:
        target_stream: IO[str] = proc.stderr
    else:
        target_stream = proc.stdout
    current_time: datetime = datetime.now()
    end_time = current_time + timedelta(seconds = timeout)
    while True:
        current_time = datetime.now()
        if current_time >= end_time:
            break
        ready_streams: SelectInfo = select.select([target_stream], [], [],
            (end_time - current_time).total_seconds())
        if len(ready_streams[0]) == 0:
            if current_time > end_time:
                break
            continue
        try:
            PlTestGlobal.linebuf += target_stream.read()
        except IOError:
            continue
        if current_time > end_time:
            break
    linebuf_parts = PlTestGlobal.linebuf.split("\n",
        maxsplit = 1)
    if len(linebuf_parts) == 2:
        PlTestGlobal.linebuf = linebuf_parts[1]
        return linebuf_parts[0] + "\n"
    return None

def ensure_running_as_root() -> None:
    """
    Ensures the test is running as root. The tests cannot function when
      running as a user as they have to execute commands as root.
    """

    if os.geteuid() != 0:
        logging.error("The tests must run as root.")
        sys.exit(1)

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

def setup_test_account(test_username: str, test_home_dir: Path) -> None:
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

def displace_old_privleap_config() -> None:
    """
    Moves the existing privleap configuration dir to a backup location so we can
      put custom config in for testing purposes.
    """

    if PlTestGlobal.privleap_conf_backup_dir.exists():
        logging.critical("Backup config dir at '%s' exist, please move or "
        "remove it before continuing.",
        str(PlTestGlobal.privleap_conf_backup_dir))
        sys.exit(1)
    ensure_path_lacks_files(PlTestGlobal.privleap_conf_dir)
    ensure_path_lacks_files(PlTestGlobal.privleap_conf_backup_dir)
    PlTestGlobal.privleap_conf_base_dir.mkdir(parents = True, exist_ok = True)
    if PlTestGlobal.privleap_conf_dir.exists():
        shutil.move(PlTestGlobal.privleap_conf_dir, PlTestGlobal.privleap_conf_backup_dir)
    PlTestGlobal.privleap_conf_dir.mkdir(parents = True, exist_ok = True)

def restore_old_privleap_config() -> None:
    """
    Moves the backup privleap configuration dir back to the original location.
    """

    ensure_path_lacks_files(PlTestGlobal.privleap_conf_dir)
    ensure_path_lacks_files(PlTestGlobal.privleap_conf_backup_dir)
    PlTestGlobal.privleap_conf_base_dir.mkdir(parents = True, exist_ok = True)
    if PlTestGlobal.privleap_conf_backup_dir.exists():
        if PlTestGlobal.privleap_conf_dir.exists():
            shutil.rmtree(PlTestGlobal.privleap_conf_dir)
        shutil.move(PlTestGlobal.privleap_conf_backup_dir, PlTestGlobal.privleap_conf_dir)
    # Make sure the "real" config dir exists even if there wasn't a backup dir
    # to move into position
    PlTestGlobal.privleap_conf_dir.mkdir(parents = True, exist_ok = True)

def stop_privleapd_service() -> None:
    """
    Stops the privleapd service. This must be called before testing starts.
    """

    try:
        subprocess.run(["systemctl", "stop", "privleapd"], check = True)
    except Exception as e:
        logging.critical("Could not stop privleapd service!",
                         exc_info = e)
        sys.exit(1)

def start_privleapd_subprocess() -> None:
    """
    Launches privleapd as a subprocess so its output can be monitored by the
      tester.
    """

    try:
        # pylint: disable=consider-using-with
        # Rationale:
        #   consider-using-with: "with" is not suitable for the architecture of
        #   this script in this scenario.
        PlTestGlobal.privleapd_proc = subprocess.Popen(["/usr/bin/privleapd"],
            stdout = subprocess.PIPE,
            stderr = subprocess.PIPE,
            encoding = "utf-8")
    except Exception as e:
        logging.critical("Could not start privleapd server!",
            exc_info = e)
    assert PlTestGlobal.privleapd_proc is not None
    assert PlTestGlobal.privleapd_proc.stdout is not None
    assert PlTestGlobal.privleapd_proc.stderr is not None
    fcntl.fcntl(PlTestGlobal.privleapd_proc.stdout.fileno(),
        fcntl.F_SETFL, os.O_NONBLOCK)
    fcntl.fcntl(PlTestGlobal.privleapd_proc.stderr.fileno(),
        fcntl.F_SETFL, os.O_NONBLOCK)
    time.sleep(1)
    early_privleapd_output: str | None = proc_try_readline(
        PlTestGlobal.privleapd_proc, PlTestGlobal.readline_timeout,
        read_stderr = True)
    if early_privleapd_output is not None:
        logging.critical("privleapd returned error messages at startup!")
        while True:
            logging.critical(early_privleapd_output)
            early_privleapd_output = proc_try_readline(
                PlTestGlobal.privleapd_proc, PlTestGlobal.readline_timeout,
                read_stderr = True)
            if early_privleapd_output is None:
                break
        sys.exit(1)
    PlTestGlobal.privleapd_running = True

def stop_privleapd_subprocess() -> None:
    """
    Stops the privleapd subprocess.
    """

    assert PlTestGlobal.privleapd_proc is not None
    try:
        PlTestGlobal.privleapd_proc.kill()
        _ = PlTestGlobal.privleapd_proc.communicate()
    except Exception as e:
        logging.critical("Could not kill privleapd!", exc_info = e)
    time.sleep(0.25)
    PlTestGlobal.privleapd_running = False

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

def write_privleap_test_config() -> None:
    """
    Writes test privleap config data.
    """

    with open(Path(PlTestGlobal.privleap_conf_dir, "unit-test.conf"), "w",
              encoding = "utf-8") as config_file:
        config_file.write(PlTestData.primary_test_config_file)

def compare_privleapd_stdout(assert_line_list: list[str], quiet: bool = False) \
        -> bool:
    """
    Compares the stdout output of privleapd with a string list, testing to see
      if each returned line matches the corresponding expected line.
    """

    assert PlTestGlobal.privleapd_proc is not None
    result: bool = True
    for line in assert_line_list:
        proc_line = proc_try_readline(PlTestGlobal.privleapd_proc,
                                      PlTestGlobal.readline_timeout, read_stderr = True)
        if proc_line != line:
            result = False
            if not quiet:
                logging.error("Mismatched server output line: '%s'", proc_line)
                logging.error("Expected server output line: '%s'", line)
    # Ensure there are no further lines in stdout. If there are, warn about each
    # unexpected line
    while True:
        proc_line = proc_try_readline(PlTestGlobal.privleapd_proc,
            PlTestGlobal.readline_timeout, read_stderr = True)
        if proc_line is None:
            break
        result = False
        if not quiet:
            logging.error("Unexpected server output line: '%s'", proc_line)
    return result

def discard_privleapd_stderr() -> None:
    """
    Ensures that the running privleapd's stdout stream has no pending contents.
    """

    if PlTestGlobal.privleapd_running:
        assert PlTestGlobal.privleapd_proc is not None
        while True:
            proc_line = proc_try_readline(PlTestGlobal.privleapd_proc,
                PlTestGlobal.readline_timeout, read_stderr = True)
            if proc_line is None:
                break

def start_privleapd_service() -> None:
    """
    Starts the privleapd service. This should only be called once all testing is
      done.
    """
    try:
        subprocess.run(["systemctl", "start", "privleapd"], check = True)
    except Exception as e:
        logging.critical("Could not start privleapd service!",
            exc_info = e)
        sys.exit(1)

def socket_send_raw_bytes(sock: socket.socket, buf: bytes) -> bool:
    """
    Sends a buffer of bytes through a socket, coping with partial sends
      properly.
    """
    buf_sent: int = 0
    while buf_sent < len(buf):
        last_sent: int = sock.send(buf[buf_sent:])
        if last_sent == 0:
            return False
        buf_sent += last_sent
    return True

class PlTestData:
    """
    Data for privleap tests.
    """

    primary_test_config_file: str = f"""[test-act-free]
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
AuthorizedGroup={PlTestGlobal.test_username}

[test-act-grouprestrict-userpermit]
Command=echo 'test-act-grouprestrict-userpermit'
AuthorizedUser={PlTestGlobal.test_username}
AuthorizedGroup=sys

[test-act-userpermit]
Command=echo 'test-act-userpermit'
AuthorizedUser={PlTestGlobal.test_username}

[test-act-grouppermit]
Command=echo 'test-act-grouppermit'
AuthorizedGroup={PlTestGlobal.test_username}

[test-act-grouppermit-userpermit]
Command=echo 'test-act-grouppermit-userpermit'
AuthorizedUser={PlTestGlobal.test_username}
AuthorizedGroup={PlTestGlobal.test_username}

[test-act-exit240]
Command=echo 'test-act-exit240'; exit 240

[test-act-stderr]
Command=1>&2 echo 'test-act-stderr'

[test-act-stdout-stderr-interleaved]
Command=echo 'stdout00'; 1>&2 echo 'stderr00'; echo 'stdout01'; 1>&2 echo 'stderr01'
"""
    invalid_filename_test_config_file: str = """[test-act-invalid]
Command=echo 'test-act-invalid'
"""
    # noinspection SpellCheckingInspection
    crash_config_file: str = """[test-act-crash]
Commandecho 'test-act-crash'
"""
    test_username_create_error: bytes \
        = (b"ERROR: privleapd encountered an error while creating a comm "
           b"socket for user '"
           + PlTestGlobal.test_username_bytes
           + b"'!\n")
    privleapd_invalid_response: bytes \
        = b"ERROR: privleapd didn't return a valid response!\n"
    specified_user_missing: bytes \
        = b"ERROR: Specified user does not exist.\n"
    apt_socket_created: bytes \
        = b"Comm socket created for user '_apt'.\n"
    apt_socket_destroyed: bytes \
        = b"Comm socket destroyed for user '_apt'.\n"
    test_username_socket_created: bytes \
        = (b"Comm socket created for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    test_username_socket_destroyed: bytes \
        = (b"Comm socket destroyed for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    test_username_socket_missing: bytes \
        = (b"Comm socket does not exist for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    test_username_socket_exists: bytes \
        = (b"Comm socket already exists for user '"
           + PlTestGlobal.test_username_bytes
           + b"'.\n")
    privleapd_connection_failed: bytes \
        = b"ERROR: Could not connect to privleapd!\n"
    root_create_error: bytes \
        = (b"ERROR: privleapd encountered an error while creating a "
           + b"comm socket for user 'root'!\n")
    root_socket_created: bytes = b"Comm socket created for user 'root'.\n"
    root_socket_destroyed: bytes = b"Comm socket destroyed for user 'root'.\n"
    leapctl_help: bytes \
        = (b"leapctl <--create|--destroy> <user>\n"
           + b"\n"
           + b"    user : The username or UID of the user account to create or destroy a\n"
           + b"           communication socket for.\n"
           + b"    --create : Specifies that leapctl should request a communication "
           + b"socket to\n"
           + b"               be created for the specified user.\n"
           + b"    --destroy : Specifies that leapctl should request a communication "
           + b"socket\n"
           + b"                to be destroyed for the specified user.\n")
    privleapd_test_act_free_failed: bytes \
        = (b"ERROR: Could not request privleapd to "
           + b"run action 'test-act-free'!\n")
    test_act_nonexistent_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-userrestrict'.\n")
    test_act_grouprestrict_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-grouprestrict'.\n")
    test_act_grouppermit_userrestrict_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-grouppermit-userrestrict'.\n")
    test_act_grouprestrict_userpermit_unauthorized: bytes \
        = (b"ERROR: You are unauthorized to run action "
           + b"'test-act-grouprestrict-userpermit'.\n")
    control_disconnect_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line "
        + "162, in handle_control_session\n",
        "    control_msg = control_session.get_msg()\n",
        "                  ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "582, in get_msg\n",
        "    recv_buf: bytes = self.__recv_msg_cautious()\n",
        "                      ^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "447, in __recv_msg_cautious\n",
        "    raise ConnectionAbortedError(\"Connection unexpectedly "
        + "closed\")\n",
        "ConnectionAbortedError: Connection unexpectedly closed\n"
    ]
    control_create_invalid_user_socket_lines: list[str] = [
        "handle_control_create_msg: WARNING: User 'nonexistent' does not "
        + "exist\n"
    ]
    create_invalid_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: WARNING: User 'nonexistent' does not "
        + "exist\n",
        "send_msg_safe: ERROR: Could not send 'CONTROL_ERROR'\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", "
        + "line 52, in send_msg_safe\n",
        "    session.send_msg(msg)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 732, in send_msg\n",
        "    self.__send_msg(msg_obj)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 691, in __send_msg\n",
        "    msg_sent: int = self.backend_socket.send(\n",
        "                    ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    destroy_invalid_user_socket_lines: list[str] = [
        "handle_control_destroy_msg: INFO: Handled DESTROY message for user "
        + "'nonexistent', socket did not exist\n"
    ]
    create_user_socket_lines: list[str] = [
        "handle_control_create_msg: INFO: Handled CREATE message for user "
        + f"'{PlTestGlobal.test_username}', socket created\n",
        "handle_control_create_msg: INFO: Handled CREATE message for user "
        + f"'{PlTestGlobal.test_username}', socket already exists\n"
    ]
    create_existing_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: INFO: Handled CREATE message for user "
        + f"'{PlTestGlobal.test_username}', socket already exists\n",
        "send_msg_safe: ERROR: Could not send 'EXISTS'\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", "
        + "line 52, in send_msg_safe\n",
        "    session.send_msg(msg)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 732, in send_msg\n",
        "    self.__send_msg(msg_obj)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 691, in __send_msg\n",
        "    msg_sent: int = self.backend_socket.send(\n",
        "                    ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    create_blocked_user_socket_lines: list[str] = [
        "handle_control_create_msg: ERROR: Failed to create socket for user "
        + f"'{PlTestGlobal.test_username}'!\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line "
        + "84, in handle_control_create_msg\n",
        "    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(\n",
        "                                     ^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "788, in __init__\n",
        "    self.backend_socket.bind(str(socket_path))\n",
        "OSError: [Errno 98] Address already in use\n"
    ]
    create_blocked_user_socket_and_bail_lines: list[str] = [
        "handle_control_create_msg: ERROR: Failed to create socket for "
        + f"user '{PlTestGlobal.test_username}'!\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", "
        + "line 84, in handle_control_create_msg\n",
        "    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(\n",
        "                                     ^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 788, in __init__\n",
        "    self.backend_socket.bind(str(socket_path))\n",
        "OSError: [Errno 98] Address already in use\n",
        "send_msg_safe: ERROR: Could not send 'CONTROL_ERROR'\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", "
        + "line 84, in handle_control_create_msg\n",
        "    comm_socket: pl.PrivleapSocket = pl.PrivleapSocket(\n",
        "                                     ^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 788, in __init__\n",
        "    self.backend_socket.bind(str(socket_path))\n",
        "OSError: [Errno 98] Address already in use\n",
        "\n",
        "During handling of the above exception, another exception "
        + "occurred:\n",
        "\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", "
        + "line 52, in send_msg_safe\n",
        "    session.send_msg(msg)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 732, in send_msg\n",
        "    self.__send_msg(msg_obj)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 691, in __send_msg\n",
        "    msg_sent: int = self.backend_socket.send(\n",
        "                    ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n",
        ]
    destroy_missing_user_socket_lines: list[str] = [
        "handle_control_destroy_msg: WARNING: Handling DESTROY, no socket to "
        + f"delete at '/run/privleapd/comm/{PlTestGlobal.test_username}'\n",
        "handle_control_destroy_msg: INFO: Handled DESTROY message for user "
        + f"'{PlTestGlobal.test_username}', socket destroyed\n"
    ]
    destroy_user_socket_and_bail_lines: list[str] = [
        "handle_control_destroy_msg: INFO: Handled DESTROY message for "
        + f"user '{PlTestGlobal.test_username}', socket destroyed\n",
        "send_msg_safe: ERROR: Could not send 'OK'\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", "
        + "line 52, in send_msg_safe\n",
        "    session.send_msg(msg)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 732, in send_msg\n",
        "    self.__send_msg(msg_obj)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", "
        + "line 691, in __send_msg\n",
        "    msg_sent: int = self.backend_socket.send(\n",
        "                    ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    privleapd_verify_not_running_twice_fail: bytes \
        = (b"verify_not_running_twice: CRITICAL: Cannot run two "
           + b"privleapd processes at the same time!\n")
    privleapd_ensure_running_as_root_fail: bytes \
        = b"ensure_running_as_root: CRITICAL: privleapd must run as root!\n"
    could_not_delete_run_privleapd: bytes \
        = (b"cleanup_old_state_dir: CRITICAL: Could not delete '/run/privleapd'!\n"
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
    test_act_invalid_unauthorized: bytes \
        = b"ERROR: You are unauthorized to run action 'test-act-invalid'.\n"
    # noinspection SpellCheckingInspection
    privleapd_config_file_parse_fail: bytes \
        = (b"parse_config_files: CRITICAL: Failed to parse config file "
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
    destroy_bad_user_socket_and_bail_lines: list[str] = [
        "handle_control_destroy_msg: INFO: Handled DESTROY message for user "
        + f"'{PlTestGlobal.test_username}', socket did not exist\n",
        "send_msg_safe: ERROR: Could not send 'NOUSER'\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line "
        + "52, in send_msg_safe\n",
        "    session.send_msg(msg)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "732, in send_msg\n",
        "    self.__send_msg(msg_obj)\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "691, in __send_msg\n",
        "    msg_sent: int = self.backend_socket.send(\n",
        "                    ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "BrokenPipeError: [Errno 32] Broken pipe\n"
    ]
    send_invalid_control_message_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line "
        + "162, in handle_control_session\n",
        "    control_msg = control_session.get_msg()\n",
        "                  ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "605, in get_msg\n",
        "    raise ValueError(\"Invalid message type '\"\n",
        "ValueError: Invalid message type 'BOB' for socket\n"
    ]
    send_corrupted_control_message_lines: list[str] = [
        "handle_control_session: ERROR: Could not get message from client!\n",
        "Traceback (most recent call last):\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleapd.py\", line "
        + "162, in handle_control_session\n",
        "    control_msg = control_session.get_msg()\n",
        "                  ^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "598, in get_msg\n",
        "    param_list, _ = self.__parse_msg_parameters(\n",
        "                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n",
        "  File \"/usr/lib/python3/dist-packages/privleap/privleap.py\", line "
        + "561, in __parse_msg_parameters\n",
        "    raise ValueError(\"recv_buf contains data past the last "
        + "string\")\n",
        "ValueError: recv_buf contains data past the last string\n"
    ]
