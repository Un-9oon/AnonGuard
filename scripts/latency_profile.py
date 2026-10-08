#!/usr/bin/python3 -I
"""Measure an explicitly supplied, owned HTTP workload; requires curl."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import os
import shutil
import subprocess
import time
from urllib.parse import urlsplit


def measure(curl, url, proxy, timeout):
    command = [curl, '-q', '--silent', '--fail', '--output', os.devnull,
               '--max-time', str(timeout), '--retry', '0',
               '--write-out', '%{http_code} %{time_total} %{size_download}']
    if proxy:
        command += ['--proxy', proxy, '--noproxy', '']
    else:
        command += ['--noproxy', '*']
    command += ['--url', url]
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout + 5, env={'PATH': '/usr/bin:/bin'})
        fields = result.stdout.split()
        status, elapsed, downloaded = int(fields[0]), float(fields[1]), int(fields[2])
        return {'success': result.returncode == 0 and 200 <= status < 300,
                'http_status': status, 'seconds': elapsed, 'downloaded_bytes': downloaded,
                'curl_exit': result.returncode}
    except (OSError, subprocess.TimeoutExpired, ValueError, IndexError):
        return {'success': False, 'http_status': 0, 'seconds': None,
                'downloaded_bytes': 0, 'curl_exit': None}


def summarize(samples, wall_seconds):
    successful = [s for s in samples if s['success']]
    times = sorted(s['seconds'] for s in successful)
    def percentile(p):
        return times[max(0, math.ceil(p * len(times)) - 1)] if times else None
    return {'attempts': len(samples), 'successes': len(successful),
            'failures': len(samples) - len(successful),
            'latency_seconds_successful_only': {str(p): percentile(p / 100) for p in (50, 95, 99)},
            'percentile_method': 'nearest rank', 'wall_seconds': wall_seconds,
            'successful_download_bytes': sum(s['downloaded_bytes'] for s in successful),
            'aggregate_download_bytes_per_second': sum(s['downloaded_bytes'] for s in successful) / wall_seconds,
            'samples': samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='Owned endpoint, without credentials')
    parser.add_argument('--proxy', help='SOCKS5 remote-DNS proxy, e.g. socks5h://127.0.0.1:9050')
    parser.add_argument('--requests', type=int, default=20)
    parser.add_argument('--concurrency', type=int, default=1)
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args()
    target = urlsplit(args.url)
    if target.scheme not in ('http', 'https') or not target.hostname or target.username or target.password:
        parser.error('Provide an HTTP(S) URL without embedded credentials')
    if args.proxy:
        proxy = urlsplit(args.proxy)
        if proxy.scheme != 'socks5h' or not proxy.hostname or proxy.username or proxy.password:
            parser.error('Use socks5h://HOST:PORT without embedded credentials')
    if not 1 <= args.requests <= 10000 or not 1 <= args.concurrency <= 64 or not 0 < args.timeout <= 120:
        parser.error('Requests 1..10000, concurrency 1..64 and timeout (0,120] required')
    curl = shutil.which('curl')
    if not curl:
        parser.error('curl is required')
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        samples = list(executor.map(lambda _: measure(curl, args.url, args.proxy, args.timeout), range(args.requests)))
    report = summarize(samples, max(time.monotonic() - started, 1e-9))
    report.update({'mode': 'socks5h' if args.proxy else 'direct', 'concurrency': args.concurrency,
                   'scope': 'HTTP completion and downloaded body bytes; not wire overhead or anonymity'})
    print(json.dumps(report, indent=2))
    return 0 if report['failures'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
