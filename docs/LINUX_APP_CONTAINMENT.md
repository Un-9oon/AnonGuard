# Experimental Linux headless application launcher

`anonguard-run-app` adds an application execution boundary to the existing network namespace. It requires privileged acceptance testing on the deployment kernel. It does not certify anonymity, defeat traffic correlation, or protect against a compromised host kernel/administrator.

## Supported contract

- Linux native x86_64/aarch64 applications; kernels supporting the requested namespaces; Bubblewrap supporting disabled nested user namespaces and bounded tmpfs. Unsupported tools, kernel policy or architecture fail before application execution, without fallback.
- A root-administered namespace created by the gateway's `--enable-firewall-killswitch` mode, with an IPv4 loopback SOCKS endpoint. IPv6 proxy endpoints are outside this launcher's profile.
- A dedicated administrator-provisioned immutable rootfs on local ext4/xfs/btrfs/tmpfs/overlay storage. Ancestors and entries must be root-owned; non-symlink entries deny group/other writes. No sockets, devices, FIFOs, set-ID files or nested mounts. Do not select general host directories, copy host secrets, or use remote/FUSE-backed overlay storage. Rootfs contents remain an administrator trust decision; the launcher does not verify downloaded image signatures.
- Dedicated host application UID/GID >=1000, separate from the daemon and other untrusted host processes. Host identity/groups are dropped before Bubblewrap; the application sees UID/GID 1000 and no capabilities.
- Noninteractive jobs: stdin/stdout/stderr are discarded. No GUI sockets, output forwarding, host data mounts, persistent writable data or host IPC brokers. Applications requiring those integrations need a separately reviewed profile.

## Execution

Install `bubblewrap`, `python3`, `libseccomp2`, `iproute2`, `nftables`, and `util-linux` from trusted OS repositories. Provision a minimal rootfs beneath a root-owned non-writable parent, including only the approved executable and runtime libraries. Create a dedicated host application account and record its numeric UID/GID.

On Ubuntu kernels enforcing AppArmor user-namespace restrictions, an administrator must authorize the trusted OS Bubblewrap executable. If the OS already ships and loads a Bubblewrap profile, keep that vendor policy. Otherwise inspect `deploy/apparmor/anonguard-bwrap` (packaged as `/usr/share/doc/anonguard/anonguard-bwrap.apparmor`), install it beneath `/etc/apparmor.d/`, and load it with `sudo apparmor_parser -r /etc/apparmor.d/anonguard-bwrap`. This executable-specific `userns` permission applies to other users of `/usr/bin/bwrap` too; it is an explicit host policy decision. Do not install a duplicate attachment alongside a vendor Bubblewrap profile, disable AppArmor globally, or turn off the kernel user-namespace restriction. The launcher never changes host AppArmor policy automatically. Without the required policy, setup refuses execution. The application still has namespace creation blocked by seccomp and Bubblewrap's nested namespace limit.

Configure authority endpoints, pins and quorum, then start the gateway in its administrative namespace mode. The packaged DynamicUser service does not automatically receive namespace privileges. Use the same namespace and IPv4 proxy port for the application:

```sh
sudo anonguard-run-app --namespace anonguard \
  --rootfs /var/lib/anonguard-apps/example \
  --host-uid APPLICATION_UID --host-gid APPLICATION_GID \
  --proxy-port 9050 -- /app/program ARGUMENTS
```

The application must explicitly use SOCKS5 at `127.0.0.1:9050` with remote hostname resolution. The launcher does not transparently proxy arbitrary networking. Applications ignoring their proxy configuration lose connectivity; direct DNS/UDP are denied. The executable path must be absolute inside the rootfs; arguments cannot override Bubblewrap options.

## Boundaries and failures

An additional namespace-local nftables input/output DROP boundary is installed atomically. It permits only IPv4 loopback TCP to the proxy and established replies, preserves gateway rules and never modifies host firewall rules. Do not change proxy ports while applications remain active. Rules survive launcher exit/crash; administrative namespace cleanup occurs only after protected applications stop.

Bubblewrap supplies private mount, process, IPC, UTS, cgroup and user namespaces, disabled nested user namespaces, capability drop and no-new-privileges. Applications receive private proc/dev, read-only rootfs, private 64 MiB scratch tmpfs and empty private run directory. The network namespace remains the prepared protected namespace. Caller descriptors are closed; only the compiled filter descriptor reaches Bubblewrap and is consumed before application exec.

The native-ABI seccomp policy blocks non-IP socket families, namespace-changing clone flags, namespace/mount operations, process/descriptor theft interfaces, io_uring setup and named kernel-administration APIs. Ordinary application syscalls remain available. This deny policy adds defense in depth; it is not a complete syscall allowlist or proof against unknown kernel vulnerabilities. Do not remove protections to accommodate unsupported applications.

Setup failures never execute the application. Application exit status is propagated. Parent-death control terminates the sandbox if the launcher dies. Helper/gateway loss closes allowed communication while direct egress stays denied. Apply CPU, process-count and total-memory budgets through the deployment's cgroup/service policy: bounded scratch alone does not contain denial of service.

## Validation and remaining gates

The privileged disposable-host fixture checks host filesystem secrecy, inherited descriptor removal, UID/groups/capabilities, no-new-privileges, blocked IPC/raw sockets/user namespaces/io_uring/descriptor theft, read-only rootfs, writable scratch, allowed proxy-endpoint flow, repeated launch and helper death. Existing namespace tests separately check direct IPv4/IPv6/DNS filtering. Neither proves every kernel escape or integration safe.

Require exact-commit CI, live checks on the deployment distribution/kernel, independent launcher/protocol review, application compatibility/load tests, resource budgets, recovery rehearsals and multi-region authority/relay evidence. macOS/Windows native containment, GUI/broker support, verified rootfs distribution and a narrow syscall allowlist remain separate work.

References: [Bubblewrap](https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html), [libseccomp rules](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html), [filter export](https://man7.org/linux/man-pages/man3/seccomp_export_bpf.3.html).
