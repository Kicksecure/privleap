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

Any messages sent by the client must be no longer than 4096 bytes long (not
including the four-byte message length header). `privleapd` will forcibly
disconnect a client that attempts to send a longer message than this. This is
expected to be enough to allow any practically-sized usernames, signal names,
and authentication data to be passed now and in the future. The server may send
messages longer than this, although it is not generally recommended.

`privleapd` understands the following messages passed via the `control` socket:

* `CREATE <username>` - Creates a communication socket for the specified user.
  `privleapd` will respond with `OK` if this succeeds, `EXISTS` if the socket
  already exists, and `CONTROL_ERROR` if this fails.
* `DESTROY <username>` - Destroys a communication socket for the specified
  user. `privleapd` will respond with `OK` if this succeeds, `NOUSER` if the
  specified user does not have a communication socket, and `CONTROL_ERROR` if
  this fails.
* `RELOAD` - Reloads configuration data. `privleapd` will respond with `OK` if
  this succeeds, and `CONTROL_ERROR` if this fails (due to invalid
  configuration). The details of the invalid configuration that lead to a
  failure will be logged.

`privleapd` can send the following messages on the `control` socket, which
clients must be able to understand:

* `OK` - The operation specified by the first client-sent message (either
  `CREATE` or `DESTROY`) in this session succeeded.
* `CONTROL_ERROR` - The operation specified by the first client-sent message
  (either `CREATE` or `DESTROY`) in this session failed.
* `EXISTS` - The first client-sent message was a `CREATE` message, but the
  username specified in the message already has a communication socket open.
* `NOUSER` - The first client-sent message was a `DESTROY` message, but the
  username specified in the message has no communication socket open.
* `PERSISTENT_USER` - The first client-sent message was a `DESTROY`
  message, but the username specified in the message is a "persistent
  user" and cannot have their socket destroyed. (See
  /etc/privleap/conf.d/README for more information on persistent users.)
* `DISALLOWED_USER` - The first client-sent message was a `CREATE` message,
  but the username specified in the message is not an "allowed user" and
  cannot have a socket created for them. (See `man privleap.conf.d ` for
  more information on allowed users.)
* `EXPECTED_DISALLOWED_USER` - The first client-sent message was a `CREATE`
  message, but the username specified in the message is an "expected
  disallowed user" and cannot have a socket created for them. (See
  `man privleap.conf.d` for more information on allowed users.)

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
* `ACCESS_CHECK <signal_name>` - Queries privleapd to determine if the caller
  is authorized to trigger the action corresponding to `<signal_name>`.
* `TERMINATE` - Instructs privleapd to immediately terminate the running
  action. The server should not attempt to send any further messages to the
  client once this message is received. 

`privleapd` can send the following messages, which clients must be able to
understand:

* `TRIGGER` - Indicates that the action requested by the previous `SIGNAL`
  message has been triggered. `privleapd` will send `TRIGGER` after *beginning*
  execution of the code specified in the action, with no respect to whether the
  action has completed or yet. If a client is satisfied that the action has
  started execution, it can disconnect from `privleapd` immediately, otherwise
  it should wait to disconnect until receiving a `RESULT_EXITCODE` message.
* `TRIGGER_ERROR` - Indicates that the action requested by the previous `SIGNAL`
  message was authorized, but launching it failed. This is usually due to
  invalid or faulty configuration. Note that `TRIGGER_ERROR` is reserved for
  actual problems *starting* the action. If the action starts successfully but
  exits non-zero, `privleapd` will still consider this a success. The client can
  use the value accompanying the `RESULT_EXITCODE` message to determine whether
  the action actually succeeded or not.
* `RESULT_STDOUT <result_stdout_text>` - Indicates that the action requested by
  the previous `SIGNAL` message wrote the given block of data to STDOUT.
  `<result_stdout_text>` is arbitrary binary data.
* `RESULT_STDERR <result_stderr_text>` - Indicates that the action requested by
  the previous `SIGNAL` message wrote the given block of data to STDERR.
  `<result_stderr_text>` is arbitrary binary data.
* `RESULT_EXITCODE <exit_code>` - Indicates that the action requested by the
  previous `SIGNAL` message has completed execution, and that it exited with
  code `<exit_code>`. `<exit_code>` is a string representing a decimal integer
  between 0 and 255.
* `AUTHORIZED` - Indicates that the user who sent an `ACCESS_CHECK` query is
  authorized to run the action specified by the `ACCESS_CHECK` message.
* `UNAUTHORIZED` - Indicates that the user attempting to trigger or query the
  specified action is not authorized to trigger that action, or that the
  signal sent by the client has no matching action. This response
  intentionally does not tell the client whether they simply aren't allowed
  to perform the action, or whether the action doesn't even exist.

`privleapd` will only parse the first one of each of the above client-sent
messages per session. `privleapd` will terminate the session immediately after
sending `AUTHORIZED`, `UNAUTHORIZED`, or `RESULT_EXITCODE`. privleapd
*may* send multiple `RESULT_STDOUT` and `RESULT_STDERR` messages in a
single session.

In actual operation, the client (most likely `leaprun`) is expected to open a
session with `privleapd` and send either a `SIGNAL` or `ACCESS_CHECK` message.
If the user is authorized to trigger the action specified in the message,
`privleapd` will respond with either `AUTHORIZED` in reply to an
`ACCESS_CHECK`, or `TRIGGER` in response to a `SIGNAL`. If privleapd is
running an action, it will send `RESULT_STDOUT` and `RESULT_STDERR` messages
as the action runs so the caller can see the output of the action.

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
