#!/usr/bin/python3 -I
"""Opt-in installed signed-browser offline refusal check. Never installs/edits host files.
Run with the client SOCKS service already stopped. This checks the browser+host
configuration as a whole; a host firewall can also account for canary refusal.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import secrets
from urllib.parse import parse_qs, urlsplit

spec = importlib.util.spec_from_file_location('session', Path(__file__).with_name('browser_session.py'))
session = importlib.util.module_from_spec(spec)
spec.loader.exec_module(session)


def preflight(browser, policy_path):
    if os.geteuid() == 0:
        raise ValueError('Run installed browser acceptance as the ordinary user')
    session.validate_policy(json.loads(session.trusted_file(policy_path)), '127.0.0.1', 9050, True, True)
    artifact = session.validate_extension(session.trusted_file(
        Path('/usr/share/anonguard/browser/isolation-signed.xpi'), maximum=1024 * 1024))
    executable = browser.resolve(strict=True)
    session.trusted_file(executable, maximum=64 * 1024 * 1024)
    session.validate_autoconfig(executable)
    with socket.socket() as probe:
        probe.settimeout(1)
        if probe.connect_ex(('127.0.0.1', 9050)) == 0:
            raise ValueError('Stop the client SOCKS service first; this is an offline refusal test')
    return executable, artifact


def validate_observation(state):
    if (state.get('policy') != session.policy('127.0.0.1', 9050, True, True)['policies']
            or state.get('locks') != {name: True for name in session.LOCKED_PREFERENCES}
            or state.get('proxy') != 1 or state.get('host') != '127.0.0.1'
            or state.get('port') != 9 or state.get('direct') is not False
            or state.get('signature_required') is not True):
        raise ValueError('Installed browser policy/locks/signature enforcement do not match required isolation profile')


def validate_refusal(uri, requested):
    parsed = urlsplit(uri)
    query = parse_qs(parsed.query)
    # HTTPS-only interstitials, stale error pages and generic connection errors
    # do not demonstrate a failed attempt through the required SOCKS proxy.
    if (parsed.scheme != 'about' or parsed.path != 'neterror'
            or query.get('e') != ['proxyConnectFailure'] or query.get('u') != [requested]):
        raise ValueError('Canary has no target-matched SOCKS connection refusal page')


def verify(browser, policy_path):
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.firefox.service import Service
    executable, artifact = preflight(browser, policy_path)
    gecko = shutil.which('geckodriver')
    if not gecko:
        raise ValueError('geckodriver is required')
    direct = threading.Event()
    stop = threading.Event()
    observer_error = threading.Event()
    with socket.socket() as canary, tempfile.TemporaryDirectory(prefix='anonguard-installed-acceptance-') as temporary:
        canary.bind(('127.0.0.1', 0)); canary.listen(); canary.settimeout(0.2)
        def observe():
            while not stop.is_set():
                try:
                    peer, _ = canary.accept()
                    direct.set(); peer.close()
                except socket.timeout:
                    pass
                except OSError:
                    if not stop.is_set():
                        observer_error.set()
                    break
        worker = threading.Thread(target=observe, daemon=True); worker.start()
        # A negative result requires a positively checked observer. This uses
        # only the owned local canary and does not exercise any external target.
        try:
            with socket.create_connection(canary.getsockname(), timeout=2):
                pass
            if not direct.wait(2) or observer_error.is_set():
                raise ValueError('Canary observer failed its positive readiness probe')
            direct.clear()
        except BaseException:
            stop.set(); worker.join(timeout=1)
            raise
        options = Options(); options.binary_location = str(executable)
        options.add_argument('-headless')
        help_text = subprocess.run([gecko, '--help'], capture_output=True, text=True, check=True, timeout=10).stdout
        args = ['--allow-system-access'] if '--allow-system-access' in help_text else []
        if not args:
            options.add_argument('-remote-allow-system-access')
        # Automation-only privileged observation; no policy/preferences overrides,
        # no temporary addon install and no disabled signature checks.
        service = Service(gecko, service_args=args, env=session.session_environment(Path(temporary)),
                          log_output=str(Path(temporary) / 'driver.log'))
        driver = None
        try:
            driver = webdriver.Firefox(options=options, service=service)
            driver.set_page_load_timeout(10); driver.set_script_timeout(10)
            driver.set_context('chrome')
            state = driver.execute_script('''return {
              policy: Services.policies.getActivePolicies(),
              locks: Object.fromEntries(arguments[0].map(k => [k, Services.prefs.prefIsLocked(k)])),
              proxy: Services.prefs.getIntPref('network.proxy.type'),
              host: Services.prefs.getStringPref('network.proxy.socks'),
              port: Services.prefs.getIntPref('network.proxy.socks_port'),
              direct: Services.prefs.getBoolPref('network.proxy.failover_direct'),
              signature_required: Services.prefs.getBoolPref('xpinstall.signatures.required', false)};''', list(session.LOCKED_PREFERENCES))
            validate_observation(state)
            deadline = time.monotonic() + 30
            addon = None
            while time.monotonic() < deadline:
                addon = driver.execute_async_script('''
                  const done = arguments[arguments.length - 1];
                  const {AddonManager} = ChromeUtils.importESModule('resource://gre/modules/AddonManager.sys.mjs');
                  AddonManager.getAddonByID('isolation@anonguard.local').then(a => done(a ? {
                    active:a.isActive, signed:a.signedState, version:a.version, disabled:a.appDisabled
                  }: null), e => done(null));''')
                if addon and addon['active']:
                    break
                time.sleep(0.2)
            if (not addon or not addon['active'] or addon['disabled'] or addon['signed'] <= 0
                    or addon['version'] != artifact['version']):
                raise ValueError('Firefox has not accepted the managed signed isolation addon')
            driver.set_context('content')
            url = f'http://127.0.0.1:{canary.getsockname()[1]}/offline-canary-{secrets.token_hex(16)}'
            try:
                driver.get(url)
            except WebDriverException:
                pass
            failed_uri = driver.execute_script('return document.documentURI')
            validate_refusal(failed_uri, url)
            # Observe beyond navigation completion/error to catch late fallback.
            if direct.wait(2):
                raise ValueError('Installed browser reached the direct loopback canary with SOCKS offline')
            if observer_error.is_set() or not worker.is_alive():
                raise ValueError('Canary observer failed; negative result cannot be accepted')
            return {'installed_policy_loaded': True, 'privacy_locks': True,
                    'managed_addon_signed_and_active': True, 'offline_direct_canary_refused': True,
                    'host_configuration_unchanged': True, 'browser_only_leak_proof': False,
                    'packet_capture_performed': False, 'production_accepted': False,
                    'browser': driver.capabilities['browserVersion']}
        finally:
            try:
                if driver:
                    driver.quit()
            finally:
                stop.set(); worker.join(timeout=1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--browser', type=Path, default=Path('/usr/bin/firefox-esr'))
    parser.add_argument('--policy-path', type=Path, default=Path('/etc/firefox/policies/policies.json'))
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.browser, args.policy_path)))
    except Exception as error:
        print(json.dumps({'accepted': False, 'error': str(error)}))
        raise SystemExit(1)
