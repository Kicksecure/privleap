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

privleap is designed for security first and usability second. As such, it may
not be suitable for all use cases where you may have previously used sudo or
the like. In particular, privleap *intentionally* does not allow two-way
communication between the non-privileged user and the actions they run. If you
need two-way communication, you are encouraged to use
[OpenDoas](https://github.com/Duncaen/OpenDoas), a fork of OpenBSD's `doas`
designed for Linux and with PAM support added. Support for two-way
communication may be added in the future if demand for such a feature is high
enough.

privleap consists of three executables: `leaprun` (the client), `leapctl` (a
privileged client for interacting with privleap's control mechanism), and
`privleapd` (the background process). `leaprun` can be used to run actions
(i.e. `leaprun stop-tor`). `privleapd` is executed by `init` as root and runs
continuously in the background, awaiting *signals* from `leaprun` or any other
application capable of speaking privleap's protocol. Note that
because privleap does not rely on SUID-root, *any* application can send
signals to `privleapd`, not just `leaprun`. `leaprun` is merely a convenience
utility to make privleap easier to use from within shell scripts and at the
command line. `leapctl` should usually only be used by other background
processes on the system, though it can be useful for debugging.

See the `leaprun(8)`, `leapctl(8)`, and `privleapd(1)` manpages for usage
instructions.

## Configuration format

privleap stores its configuration under `/etc/privleap/conf.d`. See
the `privleap-conf.d(5)` manpage for all the details of privleap
configuration.

## Protocol

The privleap protocol is defined in PROTOCOL.md. If you want to implement your
own privleap client or server, this should give you the information you need.

## Testing

The following dependencies must be installed on the host system to run the
test suite:

* autopkgtest
* debhelper
* debian-archive-keyring
* mmdebstrap
* python3

Additionally, the `/usr/bin/newuidmap` and `/usr/bin/newgidmap`
executables must be SUID-root.

It is recommended, though not necessarily required, that the host system
be running Debian 12 or a compatible derivative thereof such as
[Kicksecure](https://www.kicksecure.com/).

The test suite leverages Debian's autopkgtest tool, which allows running
the test suite in an isolated environment, unaffected by the host's
configuration for the most part. To run the tests, simply run the
`run_autopkgtest` script from the root of the source tree. The script will
function regardless of your current working directory when you
call it.

`run_autopkgtest` creates an unshare tarball under
`~/.cache/sbuild/bookworm-amd64.tar.zst` (which is where autopkgtest
expects to find it). This tarball may eventually become outdated as packages
in Debian are upgraded, or it may end up improperly built if you interrupt
`run_autopkgtest` while it is building the tarball initially. If for some
reason you need to rebuild this tarball from scratch before running the next
test, run `run_autopkgtest --reset-tarball`. This will delete the tarball
and regenerate it, then run the tests as usual.
