#!/usr/bin/python3 -I
"""Experimental disposable Firefox ESR sessions on a native client or inside the optional SOCKS-only application VM."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile


LOCKED_PREFERENCES = {
    "network.proxy.failover_direct": False,
    "network.proxy.allow_hijacking_localhost": True,
    "network.trr.mode": 5,
    "network.http.http3.enable": False,
    "media.peerconnection.enabled": False,
    "network.dns.disablePrefetch": True,
    "network.prefetch-next": False,
    "network.http.speculative-parallel-limit": 0,
    "network.captive-portal-service.enabled": False,
    "network.connectivity-service.enabled": False,
    "privacy.resistFingerprinting": True,
    "privacy.resistFingerprinting.letterboxing": True,
    "privacy.firstparty.isolate": True,
    "privacy.partition.network_state": True,
    "dom.security.https_only_mode": True,
    "browser.shell.checkDefaultBrowser": False,
    "browser.sessionstore.resume_from_crash": False,
    "browser.cache.disk.enable": False,
    "signon.rememberSignons": False,
}


def endpoint(host, port, native=False):
    address = ipaddress.IPv4Address(host)
    if native:
        if str(address) != '127.0.0.1' or port != 9050:
            raise ValueError('Native browser requires loopback SOCKS 127.0.0.1:9050')
        return str(address), port
    ranges = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if not any(address in ipaddress.IPv4Network(n) for n in ranges) or not 1024 <= port <= 65535:
        raise ValueError("Browser requires an RFC1918 IPv4 gateway and port 1024..65535")
    return str(address), port


def policy(host, port, native=False):
    host, port = endpoint(host, port, native)
    return {"policies": {
        "Proxy": {"Mode": "manual", "Locked": True, "SOCKSProxy": f"{host}:{port}",
                  "SOCKSVersion": 5, "UseProxyForDNS": True, "Passthrough": "",
                  "HTTPProxy": "", "SSLProxy": "", "AutoConfigURL": ""},
        "DNSOverHTTPS": {"Enabled": False, "Locked": True},
        "Preferences": {name: {"Value": value, "Status": "locked",
                               "Type": "boolean" if isinstance(value, bool) else "number"}
                        for name, value in LOCKED_PREFERENCES.items()},
        "ExtensionSettings": {"*": {"installation_mode": "blocked"}},
        "DisableTelemetry": True,
        "DisableFirefoxStudies": True,
        "DisableFirefoxAccounts": True,
        "DisableFormHistory": True,
        "OfferToSaveLogins": False,
        "PasswordManagerEnabled": False,
        "OverrideFirstRunPage": "about:blank",
        "OverridePostUpdatePage": "about:blank",
        "DontCheckDefaultBrowser": True,
    }}


def trusted_file(path, maximum=65536):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Trusted input must use an absolute path")
    # Ancestors must not be replaceable by the application user. Symlinked inputs
    # are deliberately refused; the browser executable is resolved separately.
    for current in (path, *path.parents):
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("Input must be root-owned with protected non-symlink ancestors")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("Input must be a regular file")
        result = stream.read(maximum + 1)
    if len(result) > maximum:
        raise ValueError("Trusted input exceeds size bound")
    return result


def validate_policy(document, host, port, native=False):
    # Exact generated policy prevents hidden proxy exceptions or weakening extras.
    if document != policy(host, port, native):
        raise ValueError("Installed browser policy differs from the supported policy")


def validate_vm(document, host, port, addresses, routes):
    if document.get("version") != 1 or document.get("gateway") != host or document.get("port") != port:
        raise ValueError("VM profile endpoint mismatch")
    nic = document.get("application_interface", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", nic) or nic == "lo":
        raise ValueError("VM profile has no valid application interface")
    network = ipaddress.IPv4Network(document["subnet"], strict=True)
    application = ipaddress.IPv4Address(document["application"])
    private = (ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if not 24 <= network.prefixlen <= 30 or not any(network.subnet_of(n) for n in private):
        raise ValueError("VM subnet is outside the supported private-address profile")
    unusable = (network.network_address, network.broadcast_address)
    if (application == ipaddress.IPv4Address(host) or application not in network
            or ipaddress.IPv4Address(host) not in network or application in unusable
            or ipaddress.IPv4Address(host) in unusable):
        raise ValueError("VM profile address mismatch")
    if {item["ifname"] for item in addresses if item["ifname"] != "lo"} != {nic}:
        raise ValueError("Application VM must have exactly its configured internal adapter")
    assigned = []
    for item in addresses:
        if item["ifname"] == "lo":
            continue
        for address in item.get("addr_info", []):
            if address.get("family") != "inet" or address.get("prefixlen") != network.prefixlen:
                raise ValueError("Unexpected IPv6 or application address prefix")
            assigned.append(address["local"])
    if assigned != [str(application)]:
        raise ValueError("Application VM address does not match profile")
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default" or route.get("gateway") or route.get("dev") not in (nic, "lo"):
            raise ValueError("Application VM has a default, gateway or foreign route")
        target = ipaddress.ip_network(destination, strict=False)
        if target.version != 4 or not (target.subnet_of(network) or target.subnet_of(ipaddress.IPv4Network("127.0.0.0/8"))):
            raise ValueError("Application VM route escapes the internal subnet")


def validate_native(document):
    if (not isinstance(document, dict) or document.get('version') != 1
            or document.get('role') != 'client' or document.get('socks') != '127.0.0.1:9050'):
        raise ValueError('Native device profile is not a supported client')
    for unit in ('anonguard-native-firewall.service', 'anonguard-client.service',
                 'anonguard-native-adapter.service'):
        subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', unit],
                       check=True, timeout=5)


def preferences(host, port, downloads):
    values = dict(LOCKED_PREFERENCES, **{
        "network.proxy.type": 1, "network.proxy.socks": host,
        "network.proxy.socks_port": port, "network.proxy.socks_version": 5,
        "network.proxy.socks_remote_dns": True, "network.proxy.no_proxies_on": "",
        "browser.startup.homepage": "about:blank", "browser.startup.page": 0,
        "browser.download.folderList": 2, "browser.download.dir": str(downloads),
    })
    return ''.join(f'user_pref({json.dumps(name)}, {json.dumps(value)});\n'
                   for name, value in sorted(values.items()))


def session_environment(root):
    # Drop inherited browser/sandbox overrides, proxy variables and preload hooks.
    keep = ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'XAUTHORITY')
    environment = {key: os.environ[key] for key in keep if key in os.environ}
    environment.update(PATH='/usr/bin:/bin', HOME=str(root), LANG='en_US.UTF-8',
                       XDG_CACHE_HOME=str(root / 'cache'), XDG_CONFIG_HOME=str(root / 'config'),
                       MOZ_CRASHREPORTER_DISABLE='1')
    return environment


def launch(browser, host, port):
    with tempfile.TemporaryDirectory(prefix='anonguard-browser-') as directory:
        root = Path(directory)
        downloads = root / 'downloads'
        downloads.mkdir(mode=0o700)
        (root / 'user.js').write_text(preferences(host, port, downloads))
        process = subprocess.Popen([str(browser), '--no-remote', '--new-instance',
                                    '--profile', str(root), 'about:blank'],
                                   env=session_environment(root), start_new_session=True)
        previous = {}
        def terminate(signum, _frame):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous[signum] = signal.signal(signum, terminate)
            return process.wait()
        finally:
            terminate(signal.SIGTERM, None)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            # Reap any remaining own browser-group children before deleting files.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--emit-policy', type=Path)
    action.add_argument('--check', action='store_true')
    action.add_argument('--launch', action='store_true')
    parser.add_argument('--proxy-host')
    parser.add_argument('--native-client', action='store_true')
    parser.add_argument('--device-profile', type=Path, default=Path('/etc/anonguard/device.json'))
    parser.add_argument('--proxy-port', type=int, default=9050)
    parser.add_argument('--policy-path', type=Path, default=Path('/etc/firefox/policies/policies.json'))
    parser.add_argument('--vm-profile', type=Path, default=Path('/etc/anonguard/vm-profile.json'))
    parser.add_argument('--browser', type=Path, default=Path('/usr/bin/firefox-esr'))
    args = parser.parse_args()
    try:
        host, port = endpoint(args.proxy_host or ('127.0.0.1' if args.native_client else '10.77.0.1'), args.proxy_port, args.native_client)
        if args.emit_policy:
            descriptor = os.open(args.emit_policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump(policy(host, port, args.native_client), stream, indent=2)
                    stream.write('\n')
            except BaseException:
                args.emit_policy.unlink()
                raise
            print(json.dumps({'policy_created': True, 'browser_accepted': False}))
            return 0
        if sys.platform != 'linux' or os.geteuid() == 0:
            raise ValueError('Browser sessions require an ordinary user in the Linux application VM')
        validate_policy(json.loads(trusted_file(args.policy_path)), host, port, args.native_client)
        if args.native_client:
            validate_native(json.loads(trusted_file(args.device_profile)))
        else:
            vm = json.loads(trusted_file(args.vm_profile))
        browser = args.browser.resolve(strict=True)
        trusted_file(browser, maximum=64 * 1024 * 1024)
        if not os.access(browser, os.X_OK):
            raise ValueError('Browser executable is not executable')
        version = subprocess.run([str(browser), '--version'], capture_output=True, text=True,
                                 check=True, timeout=10, env={'PATH': '/usr/bin:/bin'}).stdout
        if not re.search(r'Firefox (?:1[4-9]\d|[2-9]\d{2})\.\d+(?:\.\d+)*esr\b', version):
            raise ValueError('Supported foundation is maintained Firefox ESR 140 or later')
        if not args.native_client:
            addresses = json.loads(subprocess.run(['/usr/sbin/ip', '-j', 'address', 'show'],
                                                 check=True, capture_output=True, timeout=5).stdout)
            routes = json.loads(subprocess.run(['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'],
                                              check=True, capture_output=True, timeout=5).stdout)
            validate_vm(vm, host, port, addresses, routes)
        if args.check:
            print(json.dumps({'configuration_present': True, 'browser_accepted': False,
                              'policy_loaded_by_browser': 'NOT VERIFIED', 'version': version.strip()}))
            return 0
        return launch(browser, host, port)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f'Browser session refused: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
