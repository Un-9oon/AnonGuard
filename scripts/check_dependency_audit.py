#!/usr/bin/env python3
"""Reject incomplete cargo-audit output, including soft index-lookup failures."""
import argparse
import json
from pathlib import Path
import re


def validate(report, diagnostics):
    plain = re.sub(r'\x1b\[[0-9;]*m', '', diagnostics)
    if any(line.lstrip().lower().startswith('error:') for line in plain.splitlines()):
        raise ValueError('Audit diagnostics contain errors; index checks may be incomplete')
    if not isinstance(report, dict):
        raise ValueError('Invalid audit report')
    for section, field in [('database', 'advisory-count'), ('lockfile', 'dependency-count')]:
        value = report.get(section, {}).get(field)
        if type(value) is not int or value <= 0:
            raise ValueError('Missing or empty audit database/dependency inventory')
    vulnerabilities = report.get('vulnerabilities', {})
    if (vulnerabilities.get('found') is not False
            or type(vulnerabilities.get('count')) is not int
            or vulnerabilities['count'] != 0
            or vulnerabilities.get('list') != []
            or report.get('warnings') != {}):
        raise ValueError('Audit has findings, warnings, or an incomplete result')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--diagnostics', type=Path, required=True)
    args = parser.parse_args()
    try:
        validate(json.loads(args.report.read_text()), args.diagnostics.read_text())
    except (OSError, ValueError, AttributeError, TypeError) as error:
        parser.exit(1, f'Audit admission refused: {error}\n')
    print('Complete dependency audit admitted')


if __name__ == '__main__':
    main()
