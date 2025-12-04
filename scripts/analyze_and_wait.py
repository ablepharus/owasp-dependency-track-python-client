#!/usr/bin/env python3
"""Trigger vulnerability analysis on all projects and wait for completion."""

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

from owasp_dt.api.event import is_token_being_processed_1
from owasp_dt.api.finding import analyze_project
from owasp_dt.api.project import get_projects
from test import api, base_dir


def load_env() -> None:
    """Load environment variables from test.env."""
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Trigger analysis on all projects and wait for completion.",
    )
    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=300,
        help="Maximum seconds to wait for each analysis token (default: 300)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=3,
        help="Seconds between polling checks (default: 3)",
    )
    return parser.parse_args()


def iter_projects(client):
    """Iterate through all projects."""
    page_number = 1
    while True:
        response = get_projects.sync_detailed(
            client=client,
            page_number=str(page_number),
            page_size="100",
        )
        if response.status_code != 200:
            print(f"Failed to list projects on page {page_number}: status {response.status_code}", file=sys.stderr)
            break
        projects = response.parsed or []
        if not projects:
            break
        for project in projects:
            yield project
        page_number += 1


def wait_for_token(client, token: str, timeout: int, poll_interval: int) -> bool:
    """Poll token status until processing completes or timeout."""
    elapsed = 0
    while elapsed < timeout:
        resp = is_token_being_processed_1.sync_detailed(client=client, uuid=token)
        if resp.status_code != 200:
            print(f"    ⚠ Failed to check token status: {resp.status_code}", file=sys.stderr)
            return False
        
        status = resp.parsed
        if status and not status.processing:
            return True
        
        time.sleep(poll_interval)
        elapsed += poll_interval
        print(f"    ⏳ Still processing... ({elapsed}s elapsed)", end='\r')
    
    print(f"\n    ⚠ Timeout after {timeout}s")
    return False


def main() -> int:
    """Trigger analysis on all projects and wait."""
    args = parse_args()
    load_env()
    client = api.create_client_from_env()
    
    print("Collecting projects...")
    projects = list(iter_projects(client))
    
    if not projects:
        print("No projects found.")
        return 0
    
    print(f"Found {len(projects)} project(s). Triggering analysis...\n")
    
    tokens = []
    for project in projects:
        print(f"Triggering analysis for {project.name} ({project.uuid})...")
        resp = analyze_project.sync_detailed(client=client, uuid=project.uuid)
        
        if resp.status_code == 200 and resp.parsed:
            token = resp.parsed.token
            if token:
                print(f"  ✔ Analysis queued (token={token})")
                tokens.append((project.name, token))
            else:
                print(f"  ⚠ No token returned")
        else:
            print(f"  ✗ Failed: status {resp.status_code}")
    
    if not tokens:
        print("\nNo analysis tokens to wait for.")
        return 1
    
    print(f"\nWaiting for {len(tokens)} analysis job(s) to complete...")
    print(f"(timeout: {args.wait_timeout}s per job, poll interval: {args.poll_interval}s)\n")
    
    all_ok = True
    for project_name, token in tokens:
        print(f"Waiting for {project_name} (token={token})...")
        ok = wait_for_token(client, token, args.wait_timeout, args.poll_interval)
        if ok:
            print(f"  ✔ Analysis complete")
        else:
            print(f"  ✗ Analysis did not complete in time")
            all_ok = False
    
    if all_ok:
        print("\n✔ All analysis jobs completed successfully.")
        return 0
    else:
        print("\n⚠ Some analysis jobs did not complete.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

