#!/usr/bin/env python3
"""List all findings across every project in the configured Dependency-Track instance."""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback for environments without python-dotenv
    def load_dotenv(path: Path | str) -> bool:
        path = Path(path)
        if not path.exists():
            return False
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
        return True

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.project import get_projects
from owasp_dt.models.get_findings_by_project_source import GetFindingsByProjectSource
from test import api, base_dir
from owasp_dt.types import UNSET


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query all findings for every project (uses test/test.env for credentials).",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
        help="Project pagination size (default: 100).",
    )
    parser.add_argument(
        "--include-suppressed",
        action="store_true",
        help="Include suppressed findings.",
    )
    parser.add_argument(
        "--source",
        help="Optional finding source filter (maps to Dependency-Track's source query param).",
    )
    # Filtering options
    parser.add_argument(
        "--cve-id",
        dest="cve_ids",
        action="append",
        metavar="CVE",
        help="Filter by CVE ID (can be specified multiple times, supports wildcards like CVE-2023-*).",
    )
    parser.add_argument(
        "--project-id",
        dest="project_ids",
        action="append",
        metavar="UUID",
        help="Filter by project UUID (can be specified multiple times).",
    )
    parser.add_argument(
        "--project-name",
        dest="project_names",
        action="append",
        metavar="NAME",
        help="Filter by project name (can be specified multiple times, supports wildcards like ubuntu*).",
    )
    parser.add_argument(
        "--component-id",
        dest="component_ids",
        action="append",
        metavar="UUID",
        help="Filter by component UUID (can be specified multiple times).",
    )
    parser.add_argument(
        "--component-name",
        dest="component_names",
        action="append",
        metavar="NAME",
        help="Filter by component name (can be specified multiple times, supports wildcards like openssl*).",
    )
    parser.add_argument(
        "--severity",
        dest="severities",
        help="Filter by severity levels (comma-separated, e.g., HIGH,CRITICAL).",
    )
    parser.add_argument(
        "--count-only",
        action="store_true",
        help="Only show counts, not individual findings.",
    )
    return parser.parse_args()


def load_env() -> None:
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def iter_projects(client, page_size: int):
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


def matches_pattern(value: str | None, patterns: list[str] | None) -> bool:
    """Check if value matches any of the patterns (supports wildcards)."""
    if not patterns:
        return True  # No filter means match all
    if not value:
        return False
    value_lower = value.lower()
    for pattern in patterns:
        pattern_lower = pattern.lower()
        # Support wildcards using fnmatch
        if fnmatch.fnmatch(value_lower, pattern_lower):
            return True
        # Also support exact match
        if value_lower == pattern_lower:
            return True
    return False


def matches_uuid(value: str | None, uuids: list[str] | None) -> bool:
    """Check if value matches any of the UUIDs (exact match, case-insensitive)."""
    if not uuids:
        return True  # No filter means match all
    if not value:
        return False
    value_lower = value.lower()
    return any(u.lower() == value_lower for u in uuids)


def matches_severity(severity: str | None, severities: list[str] | None) -> bool:
    """Check if severity matches any of the allowed severities."""
    if not severities:
        return True  # No filter means match all
    if not severity:
        return False
    return severity.upper() in [s.upper() for s in severities]


def filter_finding(finding, args: argparse.Namespace) -> bool:
    """Return True if finding passes all filters."""
    vuln = getattr(finding, "vulnerability", None)
    component = getattr(finding, "component", None)
    
    # Filter by CVE ID
    vuln_id = getattr(vuln, "vuln_id", None) if vuln else None
    if not matches_pattern(vuln_id, args.cve_ids):
        return False
    
    # Filter by component UUID
    component_uuid = getattr(component, "uuid", None) if component else None
    if not matches_uuid(component_uuid, args.component_ids):
        return False
    
    # Filter by component name
    component_name = getattr(component, "name", None) if component else None
    if not matches_pattern(component_name, args.component_names):
        return False
    
    # Filter by severity
    severity = getattr(vuln, "severity", None) if vuln else None
    severity_list = args.severities.split(",") if args.severities else None
    if not matches_severity(severity, severity_list):
        return False
    
    return True


def filter_project(project, args: argparse.Namespace) -> bool:
    """Return True if project passes filters."""
    # Filter by project UUID
    if not matches_uuid(project.uuid, args.project_ids):
        return False
    
    # Filter by project name
    if not matches_pattern(project.name, args.project_names):
        return False
    
    return True


def list_findings(client, args: argparse.Namespace) -> None:
    total_projects = 0
    total_findings = 0
    matched_findings = 0

    # Parse severity filter once
    severity_list = args.severities.split(",") if args.severities else None
    
    # Print active filters
    filters_active = []
    if args.cve_ids:
        filters_active.append(f"CVE IDs: {', '.join(args.cve_ids)}")
    if args.project_ids:
        filters_active.append(f"Project IDs: {', '.join(args.project_ids)}")
    if args.project_names:
        filters_active.append(f"Project names: {', '.join(args.project_names)}")
    if args.component_ids:
        filters_active.append(f"Component IDs: {', '.join(args.component_ids)}")
    if args.component_names:
        filters_active.append(f"Component names: {', '.join(args.component_names)}")
    if severity_list:
        filters_active.append(f"Severities: {', '.join(severity_list)}")
    
    if filters_active:
        print("Active filters:")
        for f in filters_active:
            print(f"  • {f}")
        print()

    for project in iter_projects(client, args.page_size):
        # Apply project-level filters
        if not filter_project(project, args):
            continue
        
        total_projects += 1
        source = (
            GetFindingsByProjectSource(args.source)
            if args.source
            else UNSET
        )
        suppressed = True if args.include_suppressed else UNSET
        findings_resp = get_findings_by_project.sync_detailed(
            client=client,
            uuid=project.uuid,
            suppressed=suppressed,
            source=source,
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
        
        # Apply finding-level filters
        filtered_findings = [f for f in findings if filter_finding(f, args)]
        matched_findings += len(filtered_findings)
        
        if not filtered_findings and not args.count_only:
            # Skip projects with no matching findings unless showing all
            if filters_active:
                continue
        
        print(f"Project: {project.name} ({project.uuid}) — {len(filtered_findings)} findings")
        
        if args.count_only:
            continue
            
        for finding in filtered_findings:
            vuln = getattr(finding, "vulnerability", None)
            vuln_id = getattr(vuln, "vuln_id", None) if vuln else None
            component = getattr(finding, "component", None)
            component_name = getattr(component, "name", None) if component else None
            component_version = getattr(component, "version", None) if component else None
            component_uuid = getattr(component, "uuid", None) if component else None
            severity = getattr(vuln, "severity", None) if vuln else None
            comp_str = f"{component_name}@{component_version}" if component_version else (component_name or 'unknown')
            print(
                f"  - vuln={vuln_id or 'unknown'} "
                f"| component={comp_str} | severity={severity or 'unknown'}",
            )

    print(f"\nQueried {total_projects} project(s), {total_findings} total finding(s), {matched_findings} matched filter(s).")


def main() -> int:
    args = parse_args()
    load_env()
    client = api.create_client_from_env()
    list_findings(client, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

