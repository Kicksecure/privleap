# privleap - Limited privilege escalation framework

privleap is a privilege escalation framework similar in purpose to sudo and
doas, but very different conceptually. It is designed to allow user-level
applications to run very specific operations as root without allowing full root
control of the machine. Unlike directly executable privilege escalation
frameworks like sudo, privleap runs as a background service that listens for
signals from other applications. Each signal can request a particular,
pre-configured action to be taken. Signals are authenticated, and each action
is taken only if the signal passes authentication. Any console output from the
action is then returned to the caller. This system allows privleap to function
without being SUID-root, and avoids a lot of the potential pitfalls of sudo,
doas, run0, etc.

privleap is designed for security first and usability second. As such it may
not be suitable for all use cases where you may have previously used sudo or
the like. In particular, privleap *intentionally* does not allow two-way
communication between the non-privileged user and the actions they run. If you
need two-way communication, you are encouraged to use
[OpenDoas](https://github.com/Duncaen/OpenDoas), a fork of OpenBSD's `doas`
designed for Linux and with PAM support added. Support for two-way
communication may be added in the future if demand for such a feature is high
enough.

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
* *Result* - A message sent to an application once an action has been
  performed. May contain the stdout and stderr output from the action.
* *Challenge* - A message sent to an application when privleap needs to verify
  the user's identity.
* *Response* - A message sent to privleap to answer a previously sent
  challenge. If the response matches the challenge appropriately, identity
  verification succeeds and the requested action is triggered.

## Usage

privleap consists of three executables, `leap` (the client), `leapctl` (a
privileged client for interacting with privleap's control mechanism), and
`privleapd` (the background process). `leap` can be used to run actions (i.e.
`leap stop-tor`). `privleapd` is executed by `init` as root and runs
continuously in the background, awaiting *signals* from `leap` or any other
application that is capable of speaking privleap's protocol. Note, that because
privleap does not rely on SUID-root, *any* application can send signals to
`privleapd`, not just `leap`. `leap` is merely a convenience utility to make
privleap easier to use from within shell scripts and at the command line.
`leapctl` should usually only be used by other background processes on the
system, though it can be useful for debugging.

The full syntax of the `leap` command is:

    leap [<--response-file filename>] [<--non-interactive>] <signal_name>

    signal_name : The name of the signal that leap should send. Sending a
                  signal with a particular name will request privleapd to
                  trigger an action of the same name.
	--response-file : A file containing information that can be used to pass
	                  a challenge sent by privleapd. If this argument is not
	                  provided and privleapd sends a challenge in response to
	                  leap's signal, leap will query the user for the needed
	                  identity verification data. Otherwise, leap will use the
	                  data in this file to pass the challenge automatically.
	--non-interactive: Specifies that leap must not query the user for
	                   identity verification data. Note that if signal you are
	                   sending is expected to result in privleapd sending a
	                   challenge, you must pass a --response-file argument as
	                   well or leap will fail the challenge.

The full syntax of the `leapctl` command is:

    leapctl <--create|--destroy> <username>

    username : The name of the user account to create or destroy a
               communication socket of.
	--create : Specifies that leapctl should request a communcation socket to
	           be created for the specified user.
	--destroy : Specifies that leapctl should request a communication socket
	            to be destroyed for the specified user.

`privleapd` is not meant to be executed manually. You should start it using
your init system (`systemctl start privleapd.service`). If you want to use it
regularly, you should set it up to autostart (`systemctl enable
privleapd.service`).

## Configuration format

privleap stores its configuration under `/etc/privleap/conf.d`, which this
document will refer to as `$CONFDIR` for brevity's sake. Each file in
`$CONFDIR` must end in a `.conf` extension, and the filename must consist only
of the ASCII 7-bit characters a-z, A-Z, underscore (`_`), hyphen (`-`), and
period (`.`). Files that do not adhere to this requirement are silently
ignored. Files in nested directories underneath `$CONFDIR` are ignored.
Symlinks to files are followed so long as the symlink name adheres to the
filename requirements. (The file used as the symlink's target is not obligated
to follow the filename requirements, since its filename isn't used in any
meaningful way by privleap.)

Each configuration file under `$CONFDIR` defines an *action*. Each action can
be executed in response to a signal. The name of the action defined by the
configuration file is the configuration file's name with `.conf` trimmed off of
the end. For instance, a file named `restart-tor.conf` defines an action named
`restart-tor`.

The configuration file is formatted as follows:

* Lines starting with zero or more whitespace characters followed immediately
  by a `#` are comments. Other lines are interpreted as key/value pairs, with
  the keys and values separated by a single equals (`=`) sign.
* The following keys are recognized:
    * `Command=` - The Bash code to run when this action is triggered.
    * `AuthorizedUser=` - The user that is permitted to trigger this action. If
      this key is undefined, any user may trigger this action, otherwise only
      requests for this action from this user are accepted.
    * `AuthorizedGroup=` - The group that is permitted to trigger this action.
      If this key is undefined, any group may trigger this action, otherwise
      only requests for this action from this group are accepted. Note that if
      you are using `AuthorizedGroup`, you probably do NOT want to use
      `AuthorizedUser` in tandem, otherwise only the specified user will be able
      to trigger the action. If you want all users in a group and specific users
      outside of that group to be allowed to trigger an action, create multiple
      actions, one for the group and one for each user.
    * `VerifyIdentity=` - Whether privleap needs to verify the identity of the
      user before executing the action. One of either `true` or `false`,
      defaults to `false`. If set to `true`, privleap will not immediately run
      an action even if an authorized user requests it, but will instead
      challenge the user to prove their identity via some mechanism.
    * `IdentityMechanism=` - What mechanism to use for verifying the user's
      identity. Currently the only supported value is `password`.
        * When set to `password`, privleap will require the user to provide their
          password before a requested action is run. The password must match the
          password set in `/etc/shadow`. Note that this does **NOT** go through
          PAM!
        * In the future, perhaps other methods of identity verification can be
          added (perhaps using PAM or GPG).

## Protocol (socket-based option)

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
`<username>`. If the username `john` is being used, the string would be changed
to `CREATE john`.

When an application connects to any socket `privleapd` has open and is
listening on, it begins a session with `privleapd`. Sessions are only held open
for as long as necessary, and are closed as soon as possible.

On startup, `privleapd` creates and listens on a socket at
`/run/privleapd/control`. This socket is owned by `root:root` and uses
permissions `0600`. The containing directory `/run/privleapd` is owned by
`root:root` and uses permissions `0644`. The `control` socket is used to manage
communication sockets for each individual user account.

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
sending one of the above messages, and will ignore all but the first message the
client sends.

In actual operation, an application involved in user login is expected to send
`CREATE <username>` when `<username>` logs in, while an application invovled in
user logout is expected to send `DESTROY <username>` when the user logs out.
This ensures that only actively logged-in users have open communication
sockets. If using shell scripts for this, `leapctl --create <username>` can be
used to send `CREATE <username>`, while `leapctl --destroy <username>` can be
used to send `DESTROY <username>`.

Communication sockets are stored under `/run/privleapd/comm`. Each
communication socket is named after the user it is intended to be used by (i.e.
`<username>`). It is owned by the user and group corresponding to that user,
and uses permissions `0600`. This ensures that only the authorized user can
communicate with `privleapd` over this socket. This allows `privleapd` to
identify which user is sending messages to it.

`privleapd` understands the following messages passed via a communication
socket:

* `SIGNAL <signal_name>` - Sends a signal to `privleapd`, requesting the
  triggering of the action corresponding to `<signal_name>`.
* `RESPONSE <response_text>` - Responds to an identity verification challenge.
  `<response_text>` may contain arbitrary binary data, including space, NUL,
  and any other "difficult" bytes.

`privleapd` can send the following messages, which clients must be able to
understand:

* `TRIGGER <action_name>` - Indicates that the action specified by
  `<action_name>` has been triggered. `privleapd` will send `TRIGGER` after
  *beginning* execution of the code specified in the action, with no respect to
  whether the action has completed or yet. If a client is satisfied that the
  action has started execution, it can disconnect from `privleapd` immediately,
  otherwise it should wait to disconnect until receiving a `RESULT` message.
* `RESULT_STDOUT <action_name> <result_stdout_text>` - Indicates that the
  action specified by `<action_name>` has completed execution, and that it
  output `<result_stdout_text>` on STDOUT.
* `RESULT_STDERR <action_name> <result_stderr_text>` - Indicates that the
  action specified by `<action_name>` has completed execution, and that it
  output `<result_stderr_text>` on STDERR.
* `CHALLENGE <challenge_type>` - Requests the client to verify the identity of
  the user, using the method specified in `<challenge_type>`. Valid
  `<challenge_type>` values directly corresponnd to valid `IdentityMechanism=`
  values in privleap's configuration.
* `CHALLENGE_PASS` - Indicates that the client successfully passed the
  challenge.
* `UNAUTHORIZED` - Indicates that the client failed the challenge, that the
  user attempting to trigger the specified action is not authorized to do so,
  or that the signal send by the client has no matching action. This response
  intentionally does not tell the client whether they simply aren't allowed to
  perform the action, or whether the action doesn't even exist.

`privleapd` will only send any of the above server-sent messages exactly once
per session, and will only parse the first one of each of the above client-sent
messages per session. `privleapd` will terminate the session immediately after
sending `UNAUTHORIZED`, or immediately after sending both `RESULT_STDOUT` and
`RESULT_STDERR`. A `CHALLENGE` must be responded to by the client within 30
seconds, or `privleapd` will send `UNAUTHORIZED` and terminate the session. It
is an error for the client to send more than one of the above client-sent
messages per second, and doing so will result in `privleapd` forcibly
disconnecting the client.

In actual operation, the client (most likely `leap`) is expected to open a
session with `privleapd` and send a `SIGNAL` message. If the user it authorized
to trigger the action corresponding to this signal, `privleapd` will respond
with `TRIGGER` upon triggering the action, then will send `RESULT_STDOUT` and
`RESULT_STDERR` once the action completes. If the action requires identify
verification, `privleapd` will instead respond with `CHALLENGE`, and `leap` is
expected to reply to the challenge with a `RESPONSE`. If the response is valid,
`privleapd` will send `TRIGGER`, then `RESULT_STDOUT` and `RESULT_STDERR` once
the action is complete. If a bad `RESPONSE` is sent, if the user isn't
permitted by the configuration to trigger the action, or if the requested
action doesn't exist, `privleapd` will send `UNAUTHORIZED`.

## TODO:

* Identity verification isn't a thing yet at all.
* Probably just offload all of the identity junk to PAM, which has this down to
  a science at this point
