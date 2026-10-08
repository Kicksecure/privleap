# Agent Guidelines for privleap

This document captures security design decisions, reviewer conclusions, and
past audit findings so that future contributors (human or AI) do not re-propose
changes that have already been evaluated and resolved.

## Architecture invariants

- **No SUID binaries.** privleap runs as a background daemon (`privleapd`).
  Privilege escalation is achieved through Unix domain sockets, not SUID.
- **File permissions are the sole authentication mechanism** for socket access.
  Each comm socket is owned by its user with mode `0600`. Do not add UID peer
  credential checks (`SO_PEERCRED`) - they are redundant and can break when a
  process's UID and EUID differ.
- **One-way communication only.** stdin is never forwarded to actions. This is
  intentional to prevent interactive privilege escalation.
- **PAM environment variables are trusted.** Do not add env-var whitelisting in
  `shim.py`. If `pam_env.so` passes something through, that is the system
  administrator's decision.
- **Supplementary groups are always cleared.** `extra_groups=[]` in `shim.py`
  is the correct fix. Do not set the target user's supplementary groups -
  privleap actions are not expected to inherit them. A future
  `EnableSupplementaryGroups` config key could change this if needed.
- **No per-connection DoS rate limiting.** Each comm session runs in its own
  thread; rate limiting adds complexity without meaningful protection.

## Code style

- **Formatter:** Black. Do not reformat code in ways Black disagrees with.
- **Python version:** Targets Python 3.13+ (uses nested f-strings).
- **Comments:** Minimal. The code should be self-explanatory.

## Fixes already applied

The following bugs have been identified and fixed. Do not re-report them.

- `config_file_regex` allowed `/` and `.` (path traversal characters). Fixed:
  regex is now `r"[-A-Za-z0-9_]+\.conf\Z"`.
- `uid_regex` was missing `\Z` end anchor, accepting trailing garbage like
  `"123abc"`. Fixed: regex is now `r"[0-9]+\Z"`.
- Socket cleanup in `destroy_comm_socket()` had a non-security-sensitive
  TOCTOU race (`exists()` then `unlink()`). Fixed: call `unlink()` directly
  and catch `FileNotFoundError`.
- Config file name validation used the full path (`str(config_file)`) against
  the filename regex. Fixed: validates `config_file.name` only.
- `user_name_regex` rejected uppercase letters, although Debian's `adduser`
  accepts them by default (see `NAME_REGEX` / `SYS_NAME_REGEX` in
  `adduser.conf(5)`). Accounts such as `Example_User` could not get a comm
  socket and `leapctl@.service` restarted forever. Fixed: regex is now
  `r"[A-Za-z_][-A-Za-z0-9_]*\$?\Z"`, which matches `SYS_NAME_REGEX`. All
  account and group names reaching this regex come from root (leapctl, the
  root-only control socket, root-owned config files), so this does not widen
  what unprivileged users can send.

## Things that look like bugs but are not

- **Socket creation TOCTOU**: `bind()` creates the socket file with the process
  umask, leaving a window before `chmod()`/`chown()`. This is not a security
  issue, because privleapd sets a strict umask when launched. Attempting to
  fix this by setting a umask before creating a socket would break
  multithreading, because umask is a process-wide setting, not
  thread-specific.
- **Config directory permission check uses a path string** (follows symlinks,
  TOCTOU-vulnerable). However, due to the location of the path being read, the
  only way to exploit this is to have root privileges already, at which point
  exploitation becomes pointless.
- **`state_dir` and `comm_dir` are world-readable** (`0o755`), leaking which
  users have active sockets. Users with active sockets will either be logged
  in or configured as persistent users; the list of logged in users can be
  viewed with loginctl, and the list of persistent users can be found by
  reading privleap's world-readable configuration. Therefore this does not
  expose anything that isn't already public.
- **PAM handle reuse in `shim.py`**: the same handle is used for
  `calling_user` account check and `target_user` session open. PAM seems to be
  designed for this to work according to the `pam_set_item(3)` manpage, and
  this pattern seems to be what sudo and OpenDoas do.
- **Nonexistent users in `AuthorizedUsers`** do not cause errors. This is
  intentional - a config may reference a user that does not yet exist (e.g.
  `sysmaint`). Crashing would break package installation workflows.
- **`action_command` passed to `bash -c`** is not shell-escaped. This is by
  design - commands come from root-owned, permission-checked config files and
  are meant to be shell expressions.
- **`pwd.getpwall()`** is a valid (if unusual) Python stdlib function that
  returns all password database entries. It is not a typo.
