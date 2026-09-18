#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris (ClusterFuzzLite) harness for privleap's SERVER-SIDE wire-protocol
parser -- the only code path an unprivileged local user can reach by writing
bytes to their own comm socket, and therefore the primary place a parser bug
could turn attacker input into a daemon crash (DoS) or a mis-parsed message.

It feeds fuzz bytes to a real server-side privleap.PrivleapSession over a
socketpair (both ends bounded by a timeout so a body larger than the socket
buffer cannot deadlock the harness) and asserts the parser either rejects the
input cleanly (a controlled exception) or returns a message whose type is legal
for that socket direction -- never a cross-direction type confusion, never an
uncontrolled crash. This is the coverage-guided counterpart to the dist-ai
privleap-tests-fuzz suite.
"""

import atheris
import os
import socket
import sys

with atheris.instrument_imports():
    from privleap.privleap import PrivleapSession

## Message types the server legitimately parses on each socket direction.
COMM_RECV = ("SIGNAL", "ACCESS_CHECK", "TERMINATE")
CONTROL_RECV = ("CREATE", "DESTROY", "RELOAD")


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris contract name)
    fdp = atheris.FuzzedDataProvider(data)
    control = fdp.ConsumeBool()
    well_framed = fdp.ConsumeBool()
    body = fdp.ConsumeBytes(fdp.remaining_bytes())
    ## A correct 4-byte length prefix lets the input clear framing and reach the
    ## message tokenizer; leaving it raw also fuzzes the length-prefix path.
    raw = len(body).to_bytes(4, "big") + body if well_framed else body

    cli, srv = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    cli.settimeout(5.0)
    srv.settimeout(5.0)
    try:
        try:
            session = PrivleapSession(
                srv,
                user_id=None if control else os.getuid(),
                is_control_session=control,
            )
        except ValueError:
            ## Session SETUP, not the wire parser: a comm session resolves
            ## os.getuid() via pwd, and a run container executing the onefile
            ## under a bare numeric UID with no /etc/passwd entry raises here on
            ## ~half the inputs. That is an environment condition, not a parser
            ## finding -- skip the iteration rather than report a false crash.
            return
        try:
            cli.sendall(raw)
        except OSError:
            pass  # best-effort; the server may have closed
        try:
            cli.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        try:
            msg = session.get_msg()
        except (ValueError, ConnectionAbortedError, socket.timeout):
            return  ## controlled rejection -- the parser said "no" cleanly
        legal = CONTROL_RECV if control else COMM_RECV
        if msg.name not in legal:
            raise RuntimeError(
                "type confusion: received %r on a %s socket; input=%r"
                % (msg.name, "control" if control else "comm", raw)
            )
    finally:
        cli.close()
        srv.close()


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
