# Communication protocol for privleap

This is the specification for the privleap protocol. Ambiguities are to be
considered bugs, please report them!

## Terminology

* *Action* - A set of commands and accompanying metadata defined in one of
  privleap's configuration files. Each action corresponds to a single line of
  Bash code that is run when the action is *triggered*. Actions can only be
  triggered by users and groups authorized to trigger them, and may require the
  person operating the authorized user to prove their identity. Each action has
  a specific name.
* *Session* - A connection between a privleap client and a privleap background
  process. One or more *messages* may be sent back and forth in a session.
* *Message* - A single unit of data passed to privleap by an application, or
  passed to the application from privleap.
* *Signal* - A message sent to privleap specifying a particular action the
  application wishes to trigger. Each action has a corresponding signal with
  the same name as the action.

## Protocol

The server should assume that user-level clients are malicious and therefore
treat any data from them with the utmost caution. Additionally, the server
should aim to prevent DoS attacks caused by resource-intensive activity
patterns. In general, the server should err on the side of caution and terminate
a connection without explanation if the client is not sending data quickly
enough or sends unexpected data. This same level of care does not need to be
taken with the control socket, as it is accessibly only by root and thus is not
a danger.

Each message is formatted as a Pascal-style string that can be up to 2^32-1
bytes long. The length prefix is in big-endian byte order. The string may
contain arbitrary binary data (including NUL bytes) and should not be blindly
trusted if it comes from an untrusted source. Messages are case-sensitive.

Throughout this spec, placeholders are formatted as `<placeholder>`. These
placeholders are expected to be substituted wholesale for the actual data that
belongs there. For instance, `CREATE <username>` contains the placeholder
`<username>`. If the username `john` is being used, the string would be
changed to `CREATE john`.

When an application connects to any socket `privleapd` has open and is
listening on, it begins a session with `privleapd`. Sessions are only held
open for as long as necessary, and are closed as soon as possible.

On startup, `privleapd` creates and listens on a socket at
`/run/privleapd/control`. This socket is owned by `root:root` and uses
permissions `0600`. The containing directory `/run/privleapd` is owned by
`root:root` and uses permissions `0644`. The `control` socket is used to
manage communication sockets for each individual user account.

`privleapd` understands the following messages passed via the `control` socket:

* `CREATE <username>` - Creates a communication socket for the specified user.
  `privleapd` will respond with `OK` if this succeeds, `EXISTS` if the socket
  already exists, and `ERROR` if this fails.
* `DESTROY <username>` - Destroys a communication socket for the specified
  user. `privleapd` will respond with `OK` if this succeeds, `NOUSER` if the
  specified user does not have a communication socket, and `ERROR` if this
  fails.

`privleapd` can send the following messages on the `control` socket, which
clients must be able to understand:

* `OK` - The operation specified by the first client-sent message (either
  `CREATE` or `DESTROY`) in this session succeeded.
* `ERROR` - The operation specified by the first client-sent message (either
  `CREATE` or `DESTROY`) in this session failed.
* `EXISTS` - The first client-sent message was a `CREATE` message, but the
  username specified in the message already has a communication socket open.
* `NOUSER` - The first client-sent message was a `DESTROY` message, but the
  username specified in the message has no communication socket open.

Regardless of the reply, `privleapd` will close the session immediately after
sending one of the above messages, and will ignore all but the first message
the client sends.

In actual operation, an application involved in user login is expected to send
`CREATE <username>` when `<username>` logs in, while an application involved
in user logout is expected to send `DESTROY <username>` when the user logs
out. This ensures that only actively logged-in users have open communication
sockets. If using shell scripts for this, `leapctl --create <username>` can be
used to send `CREATE <username>`, while `leapctl --destroy <username>` can be
used to send `DESTROY <username>`.

Communication sockets are stored under `/run/privleapd/comm`. Each
communication socket is named after the user it is intended to be used by
(i.e. `<username>`). It is owned by the user and group corresponding to that
user, and uses permissions `0600`. This ensures that only the authorized user
can communicate with `privleapd` over this socket. This allows `privleapd` to
identify which user is sending messages to it.

`privleapd` understands the following messages passed via a communication
socket:

* `SIGNAL <signal_name>` - Sends a signal to `privleapd`, requesting the
  triggering of the action corresponding to `<signal_name>`.

`privleapd` can send the following messages, which clients must be able to
understand:

* `TRIGGER <action_name>` - Indicates that the action specified by
  `<action_name>` has been triggered. `privleapd` will send `TRIGGER` after
  *beginning* execution of the code specified in the action, with no respect to
  whether the action has completed or yet. If a client is satisfied that the
  action has started execution, it can disconnect from `privleapd` immediately,
  otherwise it should wait to disconnect until receiving a `RESULT_EXITCODE`
  message.
* `RESULT_STDOUT <action_name> <result_stdout_text>` - Indicates that the
  action specified by `<action_name>` has completed execution, and that it
  output `<result_stdout_text>` on STDOUT. `<result_stdout_text>` is arbitrary
  binary data.
* `RESULT_STDERR <action_name> <result_stderr_text>` - Indicates that the
  action specified by `<action_name>` has completed execution, and that it
  output `<result_stderr_text>` on STDERR. `<result_stderr_text>` is arbitrary
  binary data.
* `RESULT_EXITCODE <action_name> <exit_code>` - Indicates that the action
  specified by `<action_name>` has completed execution, and that it exited with
  code `<exit_code>`. `<exit_code>` is a string representing a decimal integer
  between 0 and 255.
* `UNAUTHORIZED` - Indicates that the user attempting to trigger the specified
  action is not authorized to do so, or that the signal send by the client has
  no matching action. This response intentionally does not tell the client
  whether they simply aren't allowed to perform the action, or whether the
  action doesn't even exist.

`privleapd` will only send any of the above server-sent messages exactly once
per session, and will only parse the first one of each of the above
client-sent messages per session. `privleapd` will terminate the session
immediately after sending `UNAUTHORIZED`, or immediately after sending both
`RESULT_EXITCODE`. It is an error for the client to send more than one of the
above client-sent messages per session, and doing so will result in `privleapd`
forcibly disconnecting the client.

In actual operation, the client (most likely `leaprun`) is expected to open a
session with `privleapd` and send a `SIGNAL` message. If the user is
authorized to trigger the action corresponding to this signal, `privleapd`
will respond with `TRIGGER` upon triggering the action, then will send
`RESULT_STDOUT` and `RESULT_STDERR` once the action completes.

## Potential future development:

* Right now privleap is designed only to allow running specific actions as
  root without a password, without the dangers of sudo. It would make it much
  more useful if it was able to handle identity verification. This could be
  done with `CHALLENGE` and `CHALLENGE_PASS` messages from the server, and
  a `RESPONSE` message from the client. This would only allow for simple
  password-based (or similar) auth though. PAM could potentially also be used,
  but trying to forward PAM auth requests over a socket could be extremely
  difficult or impossible, so in practice this would probably end up bypassing
  PAM, which is potentially livable but not ideal.
