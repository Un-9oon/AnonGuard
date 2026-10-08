#!/usr/bin/python3 -I
"""Experimental root-administered Linux headless application containment.

No caller descriptors, host mounts, output forwarding or GUI brokers are exposed.
Root and the administrator-provisioned local rootfs remain trusted.
"""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile

ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
DENIED = """setns unshare mount umount2 pivot_root chroot ptrace process_vm_readv
process_vm_writev pidfd_getfd io_uring_setup bpf perf_event_open open_by_handle_at
keyctl add_key request_key userfaultfd reboot kexec_load kexec_file_load init_module
finit_module delete_module swapon swapoff syslog acct quotactl personality clone3""".split()


class Comparison(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_uint),
                ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]


def export_filter(fd):
    if platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("Only native x86_64/aarch64 application ABIs are supported")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                          ctypes.c_int, ctypes.c_uint,
                                          ctypes.POINTER(Comparison)]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    ctx = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW; non-native ABIs killed by default.
    if not ctx:
        raise OSError("Cannot initialize syscall policy")
    try:
        def deny(name, comparison=None):
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number < 0:  # Native architecture may not implement this syscall.
                return
            ptr = ctypes.byref(comparison) if comparison is not None else None
            result = lib.seccomp_rule_add_array(ctx, 0x00050000 | errno.EPERM,
                                               number, int(comparison is not None), ptr)
            if result != 0:
                raise OSError(f"Cannot restrict syscall {name}: {result}")
        for name in DENIED:
            deny(name)
        # No pathname/abstract host IPC, netlink administration or packet sockets.
        # Only AF_INET=2 and AF_INET6=10. One comparison per rule/argument,
        # including unknown future families, rather than an incomplete denylist.
        deny("socket", Comparison(0, 2, 2, 0))  # SCMP_CMP_LT
        deny("socket", Comparison(0, 6, 10, 0))  # SCMP_CMP_GT
        for family in range(3, 10):
            deny("socket", Comparison(0, 4, family, 0))  # SCMP_CMP_EQ
        # SCMP_CMP_MASKED_EQ = 7; ordinary fork/thread clone flags remain usable.
        for flag in (0x00020000, 0x02000000, 0x04000000, 0x08000000,
                     0x10000000, 0x20000000, 0x40000000):
            deny("clone", Comparison(0, 7, flag, flag))
        if lib.seccomp_export_bpf(ctx, fd) != 0:
            raise OSError("Cannot export syscall policy")
        os.lseek(fd, 0, os.SEEK_SET)
    finally:
        lib.seccomp_release(ctx)


def validate_rootfs(path):
    root = Path(path).resolve(strict=True)
    if root == Path("/") or len(root.parts) < 3 or not root.is_dir():
        raise ValueError("Provide a dedicated application rootfs, not a host directory")
    # A writable ancestor would permit replacing the rootfs between validation and exec.
    for ancestor in (root, *root.parents):
        mode = ancestor.stat()
        if mode.st_uid != 0 or mode.st_mode & 0o022:
            raise ValueError("Rootfs and all ancestors must be root-owned and not group/other writable")
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        mount = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), left.split()[4]))
        mounts.append((mount, right.split()[0]))
        if mount != root and root in mount.parents:
            raise ValueError("Nested mounts are not supported inside the rootfs")
    backing = max((m for m in mounts if m[0] == root or m[0] in root.parents),
                  key=lambda m: len(m[0].parts))
    if backing[1] not in ("ext4", "xfs", "btrfs", "tmpfs", "overlay"):
        raise ValueError("Rootfs must use a supported local filesystem")
    for directory, dirs, files in os.walk(root, followlinks=False):
        for entry in [Path(directory), *(Path(directory) / n for n in dirs + files)]:
            mode = entry.lstat()
            if mode.st_uid != 0:
                raise ValueError("Rootfs entries must be root-owned")
            if stat.S_ISLNK(mode.st_mode):
                continue  # Resolved by the isolated root, never bind-mounted individually.
            if mode.st_mode & 0o022 or not (stat.S_ISDIR(mode.st_mode) or stat.S_ISREG(mode.st_mode)):
                raise ValueError("Rootfs must contain immutable directories/regular files/symlinks only")
            if mode.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise ValueError("Set-ID rootfs files are not supported")
    for name in ("proc", "dev", "tmp", "run"):
        if (root / name).is_symlink():
            raise ValueError("Sandbox mount targets must not be symlinks")
    return root


def sandbox_arguments(root, fd, command):
    if not command or not command[0].startswith("/") or command[0].startswith("//"):
        raise ValueError("Application command must be an absolute sandbox path")
    return ["/usr/bin/bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--disable-userns",
            "--assert-userns-disabled", "--uid", "1000", "--gid", "1000",
            "--cap-drop", "ALL", "--die-with-parent", "--new-session",
            "--ro-bind", str(root), "/", "--proc", "/proc", "--dev", "/dev",
            "--size", "67108864", "--perms", "1777", "--tmpfs", "/tmp",
            "--tmpfs", "/run", "--chdir", "/tmp",
            "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
            "--seccomp", str(fd), "--", *command]


def run(namespace, rootfs, port, command, host_uid, host_gid):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Requires a Linux administrator; never install this launcher setuid")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", namespace) or not 1 <= port <= 65535:
        raise ValueError("Invalid namespace or proxy port")
    if host_uid < 1000 or host_gid < 1000:
        raise ValueError("Use a dedicated unprivileged application UID/GID >= 1000")
    handle = Path("/run/netns") / namespace
    metadata = handle.stat()
    host = Path("/proc/self/ns/net").stat()
    if handle.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("Untrusted namespace handle")
    if (metadata.st_dev, metadata.st_ino) == (host.st_dev, host.st_ino):
        raise ValueError("Refusing application execution in the host network namespace")
    root = validate_rootfs(rootfs)
    with tempfile.TemporaryFile() as policy:
        export_filter(policy.fileno())
        arguments = sandbox_arguments(root, policy.fileno(), command)
        ip = "/usr/sbin/ip" if Path("/usr/sbin/ip").exists() else "/usr/bin/ip"
        nft = "/usr/sbin/nft" if Path("/usr/sbin/nft").exists() else "/usr/bin/nft"
        prefix = [ip, "netns", "exec", namespace]
        # Atomic extra DROP boundary. Original gateway rules remain untouched.
        # Keep this table after exit so a launcher crash cannot relax egress.
        rules = f"""add table inet anonguard_launcher
flush table inet anonguard_launcher
add chain inet anonguard_launcher output {{ type filter hook output priority 10; policy drop; }}
add chain inet anonguard_launcher input {{ type filter hook input priority 10; policy drop; }}
add rule inet anonguard_launcher output oifname "lo" ip daddr 127.0.0.1 tcp dport {port} accept
add rule inet anonguard_launcher output oifname "lo" ip saddr 127.0.0.1 tcp sport {port} ct state established accept
add rule inet anonguard_launcher input iifname "lo" ip daddr 127.0.0.1 tcp dport {port} accept
add rule inet anonguard_launcher input iifname "lo" ip saddr 127.0.0.1 tcp sport {port} ct state established accept
"""
        subprocess.run(prefix + [nft, "-f", "-"], input=rules.encode(), check=True,
                       env=ENV, close_fds=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10)
        # Enter the administrative netns first, then drop HOST identity/groups
        # before Bubblewrap maps that identity to UID/GID 1000 inside its userns.
        drop = ["/usr/bin/setpriv", f"--reuid={host_uid}", f"--regid={host_gid}",
                "--clear-groups", "--no-new-privs"]
        with subprocess.Popen(prefix + drop + arguments, env=ENV, close_fds=True,
                              pass_fds=(policy.fileno(),), stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
            try:
                return child.wait()
            except BaseException:
                child.kill()
                child.wait()
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--proxy-port", type=int, default=9050)
    parser.add_argument("--host-uid", type=int, required=True)
    parser.add_argument("--host-gid", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run(args.namespace, args.rootfs, args.proxy_port, command, args.host_uid, args.host_gid)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Application containment refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
