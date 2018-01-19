
# sandkox

Small sandbox inspired by Chromium's good ol' [suid sandbox](https://chromium.googlesource.com/chromium/src/+/lkcr/docs/linux_suid_sandbox_development.md)
& friends

# quick setup

Use the provided `Makefile`:

```
git clone https://github.com/plcp/sandkox
cd sandkox
Make
```

How to bootstrap the sandbox is left as an exercise to an attentive reader.

# tl;dr

Here are a small listing of symbols exposed by `smallkox.so`:
 - `sandkox` creates a new PID namespace, then jail the process and drops its
    privileges.

    See `jail_strap` + `jail_final` and `drop_priv` + `lock_priv`

 - `drop_priv` is a superset of `drop_root` that preserves `CAP_SET_PCAP`

    See `lock_caps`

 - `drop_root` drops root privileges, checks if effectively dropped then sets
    the process as not dumpable.

    See `drop_ptrace`

 - `drop_uid` drops privileged user to either `rgid`, `SUDO_GID` or an unused
    `uid`.
 - `drop_gid` drops privileged group to either `rgid`, `SUDO_GID` or an unused
    `gid`, also cleans supplementary groups.
 - `drop_ptrace` sets the process as not dumpable – forbids unprivileged
   `ptrace(2)` calls to attach the process.
 - `lock_priv` is defined as `lock_news`, `lock_bits` and `lock_caps` called
    in sequence.
 - `lock_caps` drop all capabilities – may require `CAP_SET_PCAP`.
 - `lock_bits` disables thread's "keep capabilities" flag, `SECBIT_NOROOT` and
   `SECBIT_NO_SETUID_FIXUP`, then locks them.

    See `capabilities(7)` + `/The securebits`

 - `lock_news` sets thread's `no_new_privs` bit to disabled – inherited, see
    linux `Documentation/prctl/no_new_privs.txt`.
 - `jail_strap` prepares a jail into `safedir` – works best
    with `/proc/self/fdinfo` – and returns `fd` for `jail_final`.

    See `jail_final`

 - `jail_final` effectively jail active process – it must be unprivileged to be
    effective.

    See `drop_root`

Note: as `jail_strap` chroot the calling process from a helper child – via
`clone(2)` + `CLONE_FS`– into `safedir`, setting `safedir` to
`/proc/self/fdinfo` prevents the unprivileged¹ parent to access the
filesystem – including `.` and `/` – as the `proc(5)` pseudofiles attached
to the privileged child are protected – see `ptrace(2)` + `/pseudofiles`.

*¹after calling `jail_strap`, a well-behaved calling process calls
`drop_priv` and `jail_final` in sequence, effectively jailing itself after
dropping its privileges.*


