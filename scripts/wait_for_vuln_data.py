#!/usr/bin/env python3
"""Wait for vulnerability data to become available and re-trigger analysis."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(path):
        """Minimal dotenv implementation."""
        if not path.exists():
            return
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip().strip('"\'')

from owasp_dt.api.vulnerability import get_all_vulnerabilities
from owasp_dt.api.metrics import get_vulnerability_metrics
from test import api, base_dir


def load_env() -> None:
    """Load environment variables from test.env."""
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Wait for vulnerability database to populate (polls every 30s).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Maximum seconds to wait (default: 1800 = 30 minutes)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Poll interval in seconds (default: 30)",
    )
    return parser.parse_args()


def check_vulnerability_data(client) -> tuple[bool, int]:
    """Check if vulnerability database has data. Returns (has_data, count)."""
    # Try to get vulnerability count
    resp = get_all_vulnerabilities.sync_detailed(client=client, page_size=1)
    
    if resp.status_code == 200 and resp.parsed:
        vulns = resp.parsed
        has_data = len(vulns) > 0
        # Try to get total count from headers
        total_count_header = resp.headers.get('X-Total-Count', '0')
        try:
            count = int(total_count_header)
        except:
            count = len(vulns)
        return has_data, count
    
    return False, 0


def main() -> int:
    """Wait for vulnerability data."""
    args = parse_args()
    load_env()
    client = api.create_client_from_env()
    
    print("Waiting for vulnerability database to populate...")
    print(f"(timeout: {args.timeout}s, checking every {args.interval}s)\n")
    
    elapsed = 0
    while elapsed < args.timeout:
        has_data, count = check_vulnerability_data(client)
        
        if has_data:
            print(f"\n✔ Vulnerability database populated with {count:,} vulnerabilities!")
            print("\nYou can now:")
            print("  1. Re-trigger analysis: python scripts/analyze_and_wait.py")
            print("  2. Check findings: python scripts/list_findings.py")
            print("  3. Filter HIGH/CRITICAL: python scripts/list_vulnerabilities.py")
            return 0
        
        print(f"⏳ No vulnerability data yet... ({elapsed}s elapsed, {count} vulnerabilities)", end='\r')
        time.sleep(args.interval)
        elapsed += args.interval
    
    print(f"\n\n⚠ Timeout after {args.timeout}s")
    print("The NVD database may still be syncing. Check Dependency-Track logs.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

