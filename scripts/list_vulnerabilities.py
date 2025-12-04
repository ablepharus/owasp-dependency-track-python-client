#!/usr/bin/env python3
"""List HIGH/CRITICAL vulnerabilities attributed more than N days ago."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
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

from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.project import get_projects
from owasp_dt.types import UNSET
from test import api, base_dir


def load_env() -> None:
    """Load environment variables from test.env."""
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="List HIGH/CRITICAL vulnerabilities attributed more than N days ago (uses test/test.env for credentials).",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Minimum age in days for vulnerabilities to include (default: 7)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
        help="Project pagination size (default: 100)",
    )
    parser.add_argument(
        "--include-suppressed",
        action="store_true",
        help="Include suppressed findings",
    )
    return parser.parse_args()


def iter_projects(client, page_size: int):
    """Iterate through all projects."""
    page_number = 1
    while True:
        response = get_projects.sync_detailed(
            client=client,
            page_number=str(page_number),
            page_size=str(page_size),
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Failed to list projects on page {page_number}: status {response.status_code}",
            )
        projects = response.parsed or []
        if not projects:
            break
        for project in projects:
            yield project
        page_number += 1


def filter_finding(finding, cutoff_timestamp_ms: int) -> bool:
    """Return True if finding is HIGH/CRITICAL and attributed older than cutoff."""
    # Check vulnerability exists and has severity
    vuln = getattr(finding, "vulnerability", None)
    if not vuln:
        return False
    
    severity = getattr(vuln, "severity", None)
    if severity not in ["HIGH", "CRITICAL"]:
        return False
    
    # Check attribution date
    attribution = getattr(finding, "attribution", None)
    if not attribution:
        return False
    
    attributed_on = getattr(attribution, "attributed_on", None)
    if not attributed_on:
        return False
    
    # Only include if attributed BEFORE cutoff (older than N days)
    if attributed_on >= cutoff_timestamp_ms:
        return False
    
    return True


def format_timestamp(timestamp_ms: int) -> str:
    """Format UNIX epoch milliseconds as human-readable date."""
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def list_vulnerabilities(client, args: argparse.Namespace) -> None:
    """List HIGH/CRITICAL vulnerabilities older than N days."""
    # Calculate cutoff timestamp: now - N days in milliseconds
    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=args.days)
    cutoff_timestamp_ms = int(cutoff_dt.timestamp() * 1000)
    
    print(f"Filtering for HIGH/CRITICAL vulnerabilities attributed before {format_timestamp(cutoff_timestamp_ms)}")
    print(f"(older than {args.days} days)\n")
    
    total_projects = 0
    total_findings = 0
    total_filtered = 0
    
    for project in iter_projects(client, args.page_size):
        total_projects += 1
        
        # Fetch findings for this project
        findings_resp = get_findings_by_project.sync_detailed(
            client=client,
            uuid=project.uuid,
            suppressed=True if args.include_suppressed else UNSET,
            source=UNSET,
        )
        
        if findings_resp.status_code != 200:
            print(
                f"[WARN] Unable to fetch findings for {project.name} ({project.uuid}): "
                f"status {findings_resp.status_code}",
                file=sys.stderr,
            )
            continue
        
        findings = findings_resp.parsed or []
        total_findings += len(findings)
        
        # Filter findings
        filtered = [f for f in findings if filter_finding(f, cutoff_timestamp_ms)]
        
        if filtered:
            print(f"\nProject: {project.name} ({project.uuid}) — {len(filtered)} HIGH/CRITICAL vulnerabilities >7 days old")
            total_filtered += len(filtered)
            
            for finding in filtered:
                vuln = getattr(finding, "vulnerability", None)
                component = getattr(finding, "component", None)
                attribution = getattr(finding, "attribution", None)
                
                vuln_id = getattr(vuln, "vuln_id", "unknown") if vuln else "unknown"
                severity = getattr(vuln, "severity", "unknown") if vuln else "unknown"
                component_name = getattr(component, "name", "unknown") if component else "unknown"
                component_version = getattr(component, "version", "") if component else ""
                attributed_on = getattr(attribution, "attributed_on", None) if attribution else None
                
                attributed_str = format_timestamp(attributed_on) if attributed_on else "unknown"
                component_str = f"{component_name}@{component_version}" if component_version else component_name
                
                print(f"  - {vuln_id} | {severity} | {component_str} | attributed: {attributed_str}")
    
    print(f"\n{'='*80}")
    print(f"Summary:")
    print(f"  Projects queried: {total_projects}")
    print(f"  Total findings: {total_findings}")
    print(f"  HIGH/CRITICAL vulnerabilities >{args.days} days old: {total_filtered}")


def main() -> int:
    """Main entry point."""
    args = parse_args()
    load_env()
    client = api.create_client_from_env()
    list_vulnerabilities(client, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

