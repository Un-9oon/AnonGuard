import copy
import unittest
from check_dependency_audit import validate


class DependencyAuditTests(unittest.TestCase):
    def setUp(self):
        self.report = {'database': {'advisory-count': 1329},
                       'lockfile': {'dependency-count': 309},
                       'vulnerabilities': {'found': False, 'count': 0, 'list': []},
                       'warnings': {}}

    def test_complete_zero_findings_control(self):
        validate(self.report, 'Updating crates.io index\n')

    def test_soft_index_failure_refuses_even_with_zero_findings(self):
        for message in ["error: couldn't check if the package is yanked: not found",
                        '\x1b[31merror:\x1b[0m index download failed']:
            with self.subTest(message=message), self.assertRaises(ValueError):
                validate(self.report, message)

    def test_findings_and_warnings_refuse(self):
        for field, value in [('count', 1), ('found', True), ('list', [{'id': 'fixture'}])]:
            changed = copy.deepcopy(self.report)
            changed['vulnerabilities'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate(changed, '')
        self.report['warnings'] = {'unmaintained': ['fixture']}
        with self.assertRaises(ValueError):
            validate(self.report, '')

    def test_empty_or_missing_inventory_refuses(self):
        for report in [{}, {'database': {'advisory-count': 0}},
                       {'database': {'advisory-count': True}}]:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate(report, '')


if __name__ == '__main__':
    unittest.main()
