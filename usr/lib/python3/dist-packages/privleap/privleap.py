#!/usr/bin/python3 -u

# Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=too-few-public-methods
# Rationale:
#   too-few-public-methods: privleap's message handling design uses lots of
#     small classes

"""
privleap.py - Backend library for privleap clients and servers.
"""

import socket
import os
import stat
import pwd
import re
from typing import Tuple
from enum import Enum
from io import StringIO

class PrivleapSocketType(Enum):
    """
    Enum for defining socket type.
    """

    CONTROL = 1
    COMMUNICATION = 2

class PrivleapValidateType(Enum):
    """
    Enum for selecting what kind of value to validate, used by
      PrivleapCommon.parse_config_file().
    """

    USER_GROUP_NAME = 1
    CONFIG_FILE = 2
    SIGNAL_NAME = 3

class PrivleapMsg:
    """
    Base class for all message classes.
    """

    def serialize(self) -> bytes:
        """Outputs raw bytes for message."""
        return b""

class PrivleapControlClientCreateMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from client to server.

    Requests creation of a comm socket for a specified user.
    """

    user_name: str | None = None

    def __init__(self, user_name: str):
        if not PrivleapCommon.validate_id(user_name,
            PrivleapValidateType.USER_GROUP_NAME):
            raise ValueError("Specified username is invalid.")
        self.user_name = user_name

    def serialize(self) -> bytes:
        assert self.user_name is not None
        return f"CREATE {self.user_name}".encode("utf-8")

class PrivleapControlClientDestroyMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from client to server.

    Requests destruction of a previously created comm socket for a specified
      user.
    """

    user_name: str | None = None

    def __init__(self, user_name: str):
        if not PrivleapCommon.validate_id(user_name,
            PrivleapValidateType.USER_GROUP_NAME):
            raise ValueError("Specified username is invalid.")
        self.user_name = user_name

    def serialize(self) -> bytes:
        assert self.user_name is not None
        return f"DESTROY {self.user_name}".encode("utf-8")

class PrivleapControlServerOkMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the requested creation or destruction operation was
      successful.
    """

    def serialize(self) -> bytes:
        return "OK".encode("utf-8")

class PrivleapControlServerControlErrorMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the requested creation or destruction operation failed.
    """

    def serialize(self) -> bytes:
        return "CONTROL_ERROR".encode("utf-8")

class PrivleapControlServerExistsMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the requested creation operation specified a user that
      already has a comm socket.
    """

    def serialize(self) -> bytes:
        return "EXISTS".encode("utf-8")

class PrivleapControlServerNouserMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the requested destruction operation specified a user that
      does not have a comm socket.
    """

    def serialize(self) -> bytes:
        return "NOUSER".encode("utf-8")

class PrivleapCommClientSignalMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from client to server.

    Requests triggering the action who's name matches the signal name.
    """

    signal_name: str | None = None

    def __init__(self, signal_name: str):
        if not PrivleapCommon.validate_id(signal_name,
            PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Specified signal name is invalid.")
        self.signal_name = signal_name

    def serialize(self) -> bytes:
        assert self.signal_name is not None
        return f"SIGNAL {self.signal_name}".encode("utf-8")

class PrivleapCommServerTriggerMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the requested action has been triggered.
    """

    action_name: str | None = None

    def __init__(self, action_name: str):
        if not PrivleapCommon.validate_id(action_name,
            PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Specified action name is invalid.")
        self.action_name = action_name

    def serialize(self) -> bytes:
        assert self.action_name is not None
        return f"TRIGGER {self.action_name}".encode("utf-8")

class PrivleapCommServerTriggerErrorMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the user was authorized to run the requested action, but
      launching the action's command failed.
    """

    action_name: str | None = None

    def __init__(self, action_name: str):
        if not PrivleapCommon.validate_id(action_name,
            PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Specified action name is invalid.")
        self.action_name = action_name

    def serialize(self) -> bytes:
        assert self.action_name is not None
        return f"TRIGGER_ERROR {self.action_name}".encode("utf-8")

class PrivleapCommServerResultStdoutMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Provides stdout data from the triggered action to the client.
    """

    action_name: str | None = None
    stdout_bytes: bytes | None = None

    def __init__(self, action_name: str, stdout_bytes: bytes):
        if not PrivleapCommon.validate_id(action_name,
            PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Specified action name is invalid.")
        self.action_name = action_name
        self.stdout_bytes = stdout_bytes

    def serialize(self) -> bytes:
        assert self.action_name is not None
        assert self.stdout_bytes is not None
        return f"RESULT_STDOUT {self.action_name} ".encode("utf-8") \
            + self.stdout_bytes

class PrivleapCommServerResultStderrMsg(PrivleapMsg):
    """Privleap message.

    Sent from server to client.

    Provides stderr data from the triggered action to the client.
    """

    action_name: str | None = None
    stderr_bytes: bytes | None = None

    def __init__(self, action_name: str, stderr_bytes: bytes):
        if not PrivleapCommon.validate_id(action_name,
            PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Specified action name is invalid.")
        self.action_name = action_name
        self.stderr_bytes = stderr_bytes

    def serialize(self) -> bytes:
        assert self.action_name is not None
        assert self.stderr_bytes is not None
        return f"RESULT_STDERR {self.action_name} ".encode("utf-8") \
            + self.stderr_bytes

class PrivleapCommServerResultExitcodeMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the requested action has completed, and exited with the
      specified exit code.
    """

    action_name: str | None = None
    # TODO: Can this be made an int instead?
    exit_code: str | None = None

    def __init__(self, action_name: str, exit_code: str):
        if not PrivleapCommon.validate_id(
            action_name, PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Specified action name is invalid.")
        self.action_name = action_name
        self.exit_code = exit_code

    def serialize(self) -> bytes:
        assert self.action_name is not None
        assert self.exit_code is not None
        return f"RESULT_EXITCODE {self.action_name} {self.exit_code}".encode(
            "utf-8")

class PrivleapCommServerUnauthorizedMsg(PrivleapMsg):
    """
    Privleap message.

    Sent from server to client.

    Indicates that the user is not authorized to run the requested action. It
      is possible the action doesn't exist, although this is not communicated
      clearly to the client for security reasons.
    """

    def serialize(self) -> bytes:
        return "UNAUTHORIZED".encode("utf-8")

class PrivleapSession:
    """
    A connection between a privleap server and client. Used to pass privleap
      messages back and forth.
    """

    backend_socket: socket.socket | None = None
    is_control_session: bool = False
    is_server_side: bool = False
    is_session_open: bool = False
    user_name: str | None = None

    # Only an extremely poorly designed client or server will ever fail to work
    # quickly enough for a 0.1-second timeout to be too short. On the other hand
    # a malicious client may attempt to lock up privleapd by sending incomplete
    # data and then hanging forever, so we timeout very quickly to avoid this
    # attack.
    def __init__(self, session_info: str | socket.socket, user_name: str = "",
        is_control_session: bool = False):
        if isinstance(session_info, str):
            if user_name != "":
                raise ValueError("user_name cannot be passed if session_info "
                    "is a string")

            if is_control_session:
                socket_path: str = PrivleapCommon.control_path

            else:
                if not PrivleapCommon.validate_id(session_info,
                    PrivleapValidateType.USER_GROUP_NAME):
                    raise ValueError("User name'"
                        + session_info
                        + "'is invalid.")

                self.user_name: str = session_info
                socket_path = PrivleapCommon.comm_path + '/' + session_info

            if not os.access(socket_path, os.R_OK | os.W_OK):
                raise PermissionError("Cannot access '"
                    + socket_path
                    + "' for reading and writing")

            self.backend_socket = socket.socket(family=socket.AF_UNIX)
            self.backend_socket.connect(socket_path)
            self.backend_socket.settimeout(0.1)

        elif isinstance(session_info, socket.socket):
            if user_name != "" \
                and not PrivleapCommon.validate_id(user_name,
                    PrivleapValidateType.USER_GROUP_NAME):
                raise ValueError("User name '" + user_name + "' is invalid.")

            self.backend_socket = session_info
            self.user_name = user_name
            self.backend_socket.settimeout(0.1)
            self.is_server_side = True

        else:
            raise ValueError("session_info must be either type 'str' or type "
                "'socket'")

        self.is_control_session = is_control_session
        self.is_session_open = True

    def __recv_msg(self) -> bytes:
        """Receives a low-level message from the backend socket. You should use
          get_msg() if you want to get an actual PrivleapMsg object back.

        DO NOT USE __recv_msg() ON THE SERVER! This is intentionally vulnerable
          to a denial-of-service attack where the remote process deliberately
          sends data slowly (or just refuses to send data at all) in order to
          lock up the server process. This is safe for the client (which may
          need to receive very large amounts of data from the server), but
          dangerous for the server (which needs to not lock up if a client tries
          to cause large delays)."""
        assert self.backend_socket is not None

        header_len: int = 4
        recv_buf: bytes = b''

        while len(recv_buf) != header_len:
            try:
                tmp_buf: bytes = self.backend_socket.recv(
                    header_len - len(recv_buf))
            except socket.timeout:
                continue
            if tmp_buf == b'':
                raise ConnectionAbortedError("Connection unexpectedly closed")
            recv_buf += tmp_buf

        msg_len: int = int.from_bytes(recv_buf, byteorder='big')

        if self.is_server_side:
            if msg_len > 4096:
                raise ValueError("Received message is too long")

        recv_buf = b''

        while len(recv_buf) != msg_len:
            try:
                tmp_buf = self.backend_socket.recv(msg_len - len(recv_buf))
            except socket.timeout:
                continue
            if tmp_buf == b'':
                raise ConnectionAbortedError("Connection unexpectedly closed")
            recv_buf += tmp_buf

        return recv_buf

    def __recv_msg_cautious(self) -> bytes:
        """Receives a low-level message from the backend socket. You should use
          get_msg() if you want to get an actual PrivleapMsg object back.

        While there aren't security issues with doing so, you probably shouldn't
          use __recv_msg_cautious() on the client. It may result in a disconnect
          while the server is still trying to send data to the client. It bails
          out if a read times out, or if it takes more than five combined loop
          iterations to read a message (thus giving at most ~0.5 seconds for the
          client to send a whole message)."""

        assert self.backend_socket is not None

        max_loops: int = 5
        header_len: int = 4
        recv_buf: bytes = b""

        while len(recv_buf) != header_len:
            if max_loops == 0:
                raise ConnectionAbortedError("Connection is too slow")
            try:
                tmp_buf: bytes = self.backend_socket.recv(
                    header_len - len(recv_buf))
            except socket.timeout as e:
                raise ConnectionAbortedError("Connection locked up") from e
            if tmp_buf == b'':
                raise ConnectionAbortedError("Connection unexpectedly closed")
            recv_buf += tmp_buf
            max_loops -= 1

        msg_len: int = int.from_bytes(recv_buf, byteorder='big')
        recv_buf = b""

        while len(recv_buf) != msg_len:
            if max_loops == 0:
                raise ConnectionAbortedError("Connection is too slow")
            try:
                tmp_buf = self.backend_socket.recv(msg_len - len(recv_buf))
            except socket.timeout as e:
                raise ConnectionAbortedError("Connection locked up") from e
            if tmp_buf == b'':
                raise ConnectionAbortedError("Connection unexpectedly closed")
            recv_buf += tmp_buf
            max_loops -= 1

        return recv_buf

    @staticmethod
    def __get_msg_type_field(recv_buf: bytes) -> str:
        """
        Gets the message type field from a privleap message. You should use
          get_msg() to get a message and then use isinstance() to determine
          which message type it is.
        """

        # Default to the length of the recv_buf if no space is found
        type_field_len: int = len(recv_buf)

        # Find first ASCII space, if it exists
        for idx, byte_val in enumerate(recv_buf):
            # Don't allow anything other than printable 7-bit-ASCII in the type
            # field
            if byte_val < 0x1F or byte_val > 0x7F:
                raise ValueError("Invalid byte found in ASCII string data")
            if byte_val == 0x20:
                type_field_len = idx
                break

        return recv_buf[:type_field_len].decode("utf-8")

    @staticmethod
    def __parse_msg_parameters(recv_buf: bytes, str_count: int,
            blob_at_end: bool) -> Tuple[list[str], bytes | None]:
        """
        Splits apart a message's data into string and binary data parameters.
          You should use get_msg() and then use the returned object's data
          fields to get information from a privleap message.
        """

        output_list: list[str] = []
        recv_buf_pos: int = 0

        # __parse_msg_parameters has to ignore the first string in the
        # message, since the first string is the message type, not a parameter.
        # Thus we have to parse one more string than specified by str_count.
        for i in range(0, str_count + 1):
            if recv_buf_pos == len(recv_buf):
                raise ValueError("Unexpected end of recv_buf hit")

            space_idx: int = len(recv_buf)
            for j in range(recv_buf_pos, len(recv_buf)):
                # Don't allow anything other than printable 7-bit-ASCII in the
                # type field
                byte_val: int = recv_buf[j]
                if byte_val < 0x1F or byte_val > 0x7F:
                    raise ValueError("Invalid byte found in ASCII string data")
                if byte_val == 0x20:
                    space_idx = j
                    break

            # Ignore the message type field, we parsed that out already in
            # __get_msg_type_field
            if i == 0:
                # If space_idx isn't equal to len(recv_buf), we hit an actual
                # space, so we want to pick up scanning immediately *after* that
                # space. If space_idx is equal to len(recv_buf) though, it's
                # already at an index equal to one past the end of the data
                # buffer, so there's no need to increment it.
                if space_idx != len(recv_buf):
                    recv_buf_pos = space_idx + 1
                else:
                    recv_buf_pos = space_idx
                continue

            # Grab the detected string
            found_string: str = recv_buf[recv_buf_pos:space_idx].decode("utf-8")
            output_list.append(found_string)

            if space_idx != len(recv_buf):
                recv_buf_pos = space_idx + 1
            else:
                recv_buf_pos = space_idx

        # At this point output_list contains all of the strings we want. If
        # blob_at_end is false, we *must* be at the end of recv_buf, or
        # someone's trying to pass buggy or malicious data. If blob_at_end is
        # true, we want to take all remaining data in the recv_buf and return it
        # as the blob.
        blob: bytes | None = None
        if blob_at_end:
            if recv_buf_pos == len(recv_buf):
                blob = b''
            else:
                blob = recv_buf[recv_buf_pos:len(recv_buf)]
        else:
            if recv_buf_pos != len(recv_buf):
                raise ValueError("recv_buf contains data past the last string")

        return output_list, blob

    def get_msg(self) -> PrivleapMsg:
        """
        Gets a message from the backend socket and returns it as a PrivleapMsg
          object. The returned object's type indicates which message was
          received, while the data fields contain the information accompanying
          the message.
        """

        if not self.is_session_open:
            raise IOError("Session is closed.")

        if self.is_server_side:
            recv_buf: bytes = self.__recv_msg_cautious()
        else:
            recv_buf = self.__recv_msg()
        msg_type_str: str = self.__get_msg_type_field(recv_buf)

        # Note, we parse the arguments of every single message type, even if the
        # message should have no arguments. This is because the parser ensures
        # that the message is well-formed, and we do not want to accept a
        # technically usable but ill-formed message for security reasons.

        # Server-side control socket, we're receiving, so expect client control
        # messages
        param_list: list[str]
        blob: bytes | None
        if self.is_control_session and self.is_server_side:
            if msg_type_str == "CREATE":
                param_list, _ = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = False)
                return PrivleapControlClientCreateMsg(param_list[0])
            if msg_type_str == "DESTROY":
                param_list, _ = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = False)
                return PrivleapControlClientDestroyMsg(param_list[0])
            raise ValueError("Invalid message type '"
                + msg_type_str
                + "' for socket")
        # Client-side control socket, we're receiving, so expect server control
        # messages
        elif self.is_control_session and not self.is_server_side:
            if msg_type_str == "OK":
                self.__parse_msg_parameters(
                    recv_buf, str_count = 0, blob_at_end = False)
                return PrivleapControlServerOkMsg()
            if msg_type_str == "CONTROL_ERROR":
                self.__parse_msg_parameters(
                    recv_buf, str_count = 0, blob_at_end = False)
                return PrivleapControlServerControlErrorMsg()
            if msg_type_str == "EXISTS":
                self.__parse_msg_parameters(
                    recv_buf, str_count = 0, blob_at_end = False)
                return PrivleapControlServerExistsMsg()
            if msg_type_str == "NOUSER":
                self.__parse_msg_parameters(
                    recv_buf, str_count = 0, blob_at_end = False)
                return PrivleapControlServerNouserMsg()
            raise ValueError("Invalid message type '"
                + msg_type_str
                + "' for socket")
        # Server-side comm socket, we're receiving, so expect client comm
        # messages
        elif not self.is_control_session and self.is_server_side:
            if msg_type_str == "SIGNAL":
                param_list, _ = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = False)
                return PrivleapCommClientSignalMsg(param_list[0])
            raise ValueError("Invalid message type '"
                + msg_type_str
                + "' for socket")
        # Client-side comm socket, we're receiving, so expect server comm
        # messages
        else:
            if msg_type_str == "TRIGGER":
                param_list, _ = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = False)
                return PrivleapCommServerTriggerMsg(param_list[0])
            if msg_type_str == "TRIGGER_ERROR":
                param_list, _ = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = False)
                return PrivleapCommServerTriggerErrorMsg(param_list[0])
            if msg_type_str == "RESULT_STDOUT":
                param_list, blob = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = True)
                assert blob is not None
                return PrivleapCommServerResultStdoutMsg(param_list[0], blob)
            if msg_type_str == "RESULT_STDERR":
                param_list, blob = self.__parse_msg_parameters(
                    recv_buf, str_count = 1, blob_at_end = True)
                assert blob is not None
                return PrivleapCommServerResultStderrMsg(param_list[0], blob)
            if msg_type_str == "RESULT_EXITCODE":
                param_list, _ = self.__parse_msg_parameters(
                    recv_buf, str_count = 2, blob_at_end = False)
                return PrivleapCommServerResultExitcodeMsg(
                    param_list[0], param_list[1])
            if msg_type_str == "UNAUTHORIZED":
                self.__parse_msg_parameters(
                    recv_buf, str_count = 0, blob_at_end = False)
                return PrivleapCommServerUnauthorizedMsg()
            raise ValueError("Invalid message type '"
                + msg_type_str
                + "' for socket")

    def __send_msg(self, msg_obj: PrivleapMsg) -> None:
        """
        Sends a message to the remote client or server. **This does not validate
          that the message being sent is appropriate coming from the sender.**
          You should use send_msg() instead.
        """

        assert self.backend_socket is not None

        msg_bytes: bytes = msg_obj.serialize()
        msg_len_bytes: bytes = len(msg_bytes).to_bytes(4, byteorder='big')
        msg_payload: bytes = msg_len_bytes + msg_bytes
        msg_payload_sent: int = 0
        while msg_payload_sent < len(msg_payload):
            msg_sent: int = self.backend_socket.send(
                msg_payload[msg_payload_sent:])
            if msg_sent == 0:
                raise ConnectionAbortedError("Connection unexpectedly closed")
            msg_payload_sent += msg_sent

    def send_msg(self, msg_obj: PrivleapMsg) -> None:
        """
        Sends a message to the remote client or server. Validates that the
          message being sent is appropriate coming from the sender.
        """

        assert self.backend_socket is not None

        if not self.is_session_open:
            raise IOError("Session is closed.")

        msg_obj_type: type = type(msg_obj)

        if self.is_control_session and self.is_server_side:
            if msg_obj_type != PrivleapControlServerOkMsg \
                and msg_obj_type != PrivleapControlServerControlErrorMsg \
                and msg_obj_type != PrivleapControlServerExistsMsg \
                and msg_obj_type != PrivleapControlServerNouserMsg:
                raise ValueError("Invalid message type for socket.")
        elif self.is_control_session and not self.is_server_side:
            if msg_obj_type != PrivleapControlClientCreateMsg \
                and msg_obj_type != PrivleapControlClientDestroyMsg:
                raise ValueError("Invalid message type for socket.")
        elif not self.is_control_session and self.is_server_side:
            if msg_obj_type != PrivleapCommServerTriggerMsg \
                and msg_obj_type != PrivleapCommServerTriggerErrorMsg \
                and msg_obj_type != PrivleapCommServerResultStdoutMsg \
                and msg_obj_type != PrivleapCommServerResultStderrMsg \
                and msg_obj_type != PrivleapCommServerResultExitcodeMsg \
                and msg_obj_type != PrivleapCommServerUnauthorizedMsg:
                raise ValueError("Invalid message type for socket.")
        else:
            if msg_obj_type != PrivleapCommClientSignalMsg:
                raise ValueError("Invalid message type for socket.")

        self.__send_msg(msg_obj)

    def close_session(self) -> None:
        assert self.backend_socket is not None
        self.backend_socket.shutdown(socket.SHUT_RDWR)
        self.backend_socket.close()
        self.is_session_open = False

class PrivleapSocket:
    """
    A server-side listening socket for privleap control and comm connections.
      Use this only on the server for listening for incoming connections. Both
      the server and client should use PrivleapSession objects for actual
      communication.
    """

    backend_socket: socket.socket | None = None
    socket_type: PrivleapSocketType | None = None
    user_name: str | None = None

    def __init__(self, socket_type: PrivleapSocketType, user_name: str = ""):
        if socket_type == PrivleapSocketType.CONTROL:
            if user_name != "":
                raise ValueError("user_name is only valid with "
                    "PrivleapSocketType.COMMUNICATION")
            self.backend_socket = socket.socket(family = socket.AF_UNIX)
            self.backend_socket.bind(PrivleapCommon.control_path)
            os.chown(PrivleapCommon.control_path, 0, 0)
            os.chmod(PrivleapCommon.control_path, stat.S_IRUSR | stat.S_IWUSR)
            self.backend_socket.listen(10)
        else:
            if user_name == "":
                raise ValueError("user_name must be provided when using "
                    "PrivleapSocketType.COMMUNICATION")

            if not PrivleapCommon.validate_id(
                user_name, PrivleapValidateType.USER_GROUP_NAME):
                raise ValueError("User name '" + user_name + "' is invalid.")

            try:
                user_info: pwd.struct_passwd = pwd.getpwnam(user_name)
                target_uid: int = user_info.pw_uid
                target_gid: int = user_info.pw_gid
            except:
                raise ValueError("User '" + user_name + "' does not exist.")

            self.backend_socket = socket.socket(family = socket.AF_UNIX)
            socket_path = PrivleapCommon.comm_path + "/" + user_name
            self.backend_socket.bind(socket_path)
            os.chown(socket_path, target_uid, target_gid)
            os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR)
            self.backend_socket.listen(10)
            self.user_name = user_name

        self.socket_type = socket_type

    def get_session(self) -> PrivleapSession:
        """
        Gets a session from the listening socket. For those used to using
          sockets directly, this is an analogue to socket.accept().
        """

        assert self.backend_socket is not None

        # socket.accept returns a (socket, address) tuple, we only need the
        # socket from this
        session_socket: socket.socket = self.backend_socket.accept()[0]
        if self.socket_type == PrivleapSocketType.CONTROL:
            return PrivleapSession(session_socket, is_control_session = True)
        else:
            assert self.user_name is not None
            return PrivleapSession(
                session_socket,
                user_name = self.user_name,
                is_control_session = False)

class PrivleapAction:
    """
    A single action defined by privleap's configuration.
    """

    action_name = None
    action_command = None
    auth_user = None
    auth_group = None
    target_user = "root"
    target_group = "root"

    def __init__(self,
        action_name: str = "",
        action_command: str = "",
        auth_user: str = "",
        auth_group: str = "",
        target_user: str = "",
        target_group: str = ""):

        if action_name == "":
            raise ValueError("action_name is empty")
        if action_command == "":
            raise ValueError("action_command is empty")
        if target_user == "":
            target_user = "root"
        if target_group == "":
            target_group = "root"

        if not PrivleapCommon.validate_id(
            action_name, PrivleapValidateType.SIGNAL_NAME):
            raise ValueError("Action name '" + action_name + "' is invalid")

        for key, value in { "auth_user": auth_user,
            "auth_group": auth_group,
            "target_user": target_user,
            "target_group": target_group }.items():

            if not value == "" and not PrivleapCommon.validate_id(
                value, PrivleapValidateType.USER_GROUP_NAME):
                raise ValueError("Invalid value '"
                    + value
                    + "' for argument '"
                    + key
                    + "'")

        self.action_name = action_name
        self.action_command = action_command
        self.auth_user = auth_user if auth_user != "" else None
        self.auth_group = auth_group if auth_user != "" else None
        self.target_user = target_user
        self.target_group = target_group

class PrivleapCommon:
    """
    Common constants and functions used throughout privleap.
    """

    state_dir: str = "/run/privleapd"
    control_path: str = state_dir + "/control"
    comm_path: str = state_dir + "/comm"
    config_file_regex: re.Pattern[str] \
        = re.compile(r"[-A-Za-z0-9_./]+\.conf\Z")
    user_name_regex: re.Pattern[str] \
        = re.compile(r"[A-Za-z_][-A-Za-z0-9_]*\$?\Z")
    signal_name_regex: re.Pattern[str] \
        = re.compile(r"[-A-Za-z0-9_.]+\Z")

    @staticmethod
    def validate_id(id_string: str, validate_type: PrivleapValidateType)\
        -> bool:
        """
        Validates id_string against a predefined regex. The regex used for
          validation is specified by validate_type.
        """

        if len(id_string) > 100:
            return False

        if validate_type is PrivleapValidateType.USER_GROUP_NAME:
            if PrivleapCommon.user_name_regex.match(id_string):
                return True
        elif validate_type is PrivleapValidateType.CONFIG_FILE:
            if PrivleapCommon.config_file_regex.match(id_string):
                return True
        elif validate_type is PrivleapValidateType.SIGNAL_NAME:
            if PrivleapCommon.signal_name_regex.match(id_string):
                return True

        return False

    @staticmethod
    def parse_config_file(config_data: str) -> list[PrivleapAction]:
        """
        Parses the data from a privleap configuration file and returns all
        privleap actions defined therein.
        """

        output_list: list[PrivleapAction] = list()
        conf_stream: StringIO = StringIO(config_data)
        detect_comment_regex: re.Pattern[str] = re.compile(r"\s*#")
        detect_header_regex: re.Pattern[str] = re.compile(r"\[.*]\Z")
        current_action_name: str = ""
        current_action_command: str = ""
        current_auth_user: str = ""
        current_auth_group: str = ""
        current_target_user: str = ""
        current_target_group: str = ""
        first_header_parsed: bool = False
        for line in conf_stream:
            line = line.strip()
            if line == "":
                continue

            if detect_comment_regex.match(line):
                continue

            if detect_header_regex.match(line):
                if first_header_parsed:
                    output_list.append(PrivleapAction(current_action_name,
                        current_action_command,
                        current_auth_user,
                        current_auth_group,
                        current_target_user,
                        current_target_group))
                    # We don't need to zero out current_action_name since we set
                    # its value below.
                    # current_action_name = ""
                    current_action_command = ""
                    current_auth_user = ""
                    current_auth_group = ""
                    current_target_user = ""
                    current_target_group = ""
                else:
                    first_header_parsed = True

                current_action_name = line[1:len(line)-1]
                continue

            line_parts: list[str] = line.split('=', maxsplit = 1)
            if len(line_parts) != 2:
                raise ValueError("Invalid config line '" + line +"'")

            config_key: str = line_parts[0]
            config_val: str = line_parts[1]
            if config_key == "Command":
                current_action_command = config_val
            elif config_key == "AuthorizedUser":
                current_auth_user = config_val
            elif config_key == "AuthorizedGroup":
                current_auth_group = config_val
            elif config_key == "TargetUser":
                current_target_user = config_val
            elif config_key == "TargetGroup":
                current_target_group = config_val
            else:
                raise ValueError("Unrecognized key '" + config_key +"' found")

        # The last action in the file won't be in the list yet, add it now
        output_list.append(PrivleapAction(current_action_name,
            current_action_command,
            current_auth_user,
            current_auth_group,
            current_target_user,
            current_target_group))

        return output_list
