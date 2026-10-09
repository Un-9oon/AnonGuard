#!/usr/bin/python3 -I
"""Load generated enterprise policy in a disposable Firefox automation profile.
Uses a private Firefox executable layout with distribution/policies.json; never installs host policy.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('session',ROOT/'scripts/browser_session.py')
session=importlib.util.module_from_spec(spec);spec.loader.exec_module(session)

class LoadedPolicy(unittest.TestCase):
    def test_ordinary_policy(self):
        self.verify(False)

    def test_isolated_policy(self):
        self.verify(True)

    def verify(self, isolated):
        with tempfile.TemporaryDirectory() as temporary:
            policy=Path(temporary)/'policy.json'
            document=session.policy('127.0.0.1',9050,True,isolated=isolated)
            policy.write_text(json.dumps(document))
            vendor=Path(os.environ.get('ANONGUARD_FIREFOX') or shutil.which('firefox-esr')).resolve()
            layout=Path(temporary)/'firefox';layout.mkdir()
            # Copy only executable entry points; read-only vendor libraries and
            # resources remain symlinked. The new app layout owns its policy.
            for source in vendor.parent.iterdir():
                if source.name=='distribution':continue
                destination=layout/source.name
                if source.name=='defaults':
                    shutil.copytree(source,destination)
                elif source.name in ('firefox','firefox-esr','firefox-bin') and source.is_file():
                    shutil.copy2(source,destination)
                else:destination.symlink_to(source,target_is_directory=source.is_dir())
            # Upstream Mozilla archives may omit defaults/pref entirely.
            # Create it in the disposable layout, never in the vendor install.
            (layout/'defaults/pref').mkdir(parents=True,exist_ok=True)
            (layout/'anonguard.cfg').write_text(session.autoconfig())
            (layout/'defaults/pref/anonguard.js').write_text(session.AUTOCONFIG_LOADER)
            (layout/'distribution').mkdir()
            shutil.copy2(policy,layout/'distribution/policies.json')
            options=Options();options.binary_location=str(layout/vendor.name)
            options.add_argument('-headless');options.add_argument('-remote-allow-system-access')
            environment=dict(os.environ,MOZ_AUTOMATION='1')
            service=Service(os.environ.get('ANONGUARD_GECKODRIVER') or shutil.which('geckodriver'),env=environment,log_output=str(Path(temporary)/'driver.log'))
            driver=webdriver.Firefox(options=options,service=service)
            try:
                driver.set_context('chrome')
                observed=driver.execute_script('''
                  return {active: Services.policies.getActivePolicies(),
                    status: Services.policies.status,
                    locks: Object.fromEntries(arguments[0].map(name => [name, Services.prefs.prefIsLocked(name)])),
                    proxy: Services.prefs.getIntPref('network.proxy.type'),
                    host: Services.prefs.getStringPref('network.proxy.socks'),
                    port: Services.prefs.getIntPref('network.proxy.socks_port'),
                    remoteDNS: Services.prefs.getBoolPref('network.proxy.socks_remote_dns'),
                    failover: Services.prefs.getBoolPref('network.proxy.failover_direct')};
                ''',list(session.LOCKED_PREFERENCES))
                self.assertEqual(observed['active'],document['policies'])
                self.assertTrue(all(observed['locks'].values()),observed['locks'])
                self.assertEqual(observed['proxy'],1)
                self.assertEqual(observed['host'],'127.0.0.1')
                self.assertEqual(observed['port'],9 if isolated else 9050)
                self.assertTrue(observed['remoteDNS']);self.assertFalse(observed['failover'])
                print(json.dumps({'browser':driver.capabilities['browserVersion'],'generated_policy_loaded':True,'preferences_locked':True,'host_policy_installed':False,'production_accepted':False}))
            finally:driver.quit()

if __name__=='__main__':unittest.main()
