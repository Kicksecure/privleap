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

## Usage

privleap consists of three executables, `leaprun` (the client), `leapctl` (a
privileged client for interacting with privleap's control mechanism), and
`privleapd` (the background process). `leaprun` can be used to run actions
(i.e. `leaprun stop-tor`). `privleapd` is executed by `init` as root and runs
continuously in the background, awaiting *signals* from `leaprun` or any other
application that is capable of speaking privleap's protocol. Note, that
because privleap does not rely on SUID-root, *any* application can send
signals to `privleapd`, not just `leaprun`. `leaprun` is merely a convenience
utility to make privleap easier to use from within shell scripts and at the
command line. `leapctl` should usually only be used by other background
processes on the system, though it can be useful for debugging.

The full syntax of the `leaprun` command is:

    leaprun <signal_name>

    signal_name : The name of the signal that leap should send. Sending a
                  signal with a particular name will request privleapd to
                  trigger an action of the same name.

The full syntax of the `leapctl` command is:

    leapctl <--create|--destroy> <user>

    user : The username or UID of the user account to create or destroy a
           communication socket of.
	--create : Specifies that leapctl should request a communication socket to
	           be created for the specified user.
	--destroy : Specifies that leapctl should request a communication socket
	            to be destroyed for the specified user.

`privleapd` is not meant to be executed manually. You should start it using
your init system (`systemctl start privleapd.service`). If you want to use it
regularly, you should set it up to autostart (`systemctl enable
privleapd.service`).

## Configuration format

privleap stores its configuration under `/etc/privleap/conf.d`. See etc/privleap/conf.d/README in the code for all the details of privleap configuration.

## Protocol

The privleap protocol is defined in PROTOCOL.md. If you want to implement your
own privleap client or server, this should give you the information you need.
