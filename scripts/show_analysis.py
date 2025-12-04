#!/usr/bin/env python3
"""Show analysis details for findings in the configured Dependency-Track instance."""

from __future__ import annotations

import argparse
import fnmatch
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

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

from owasp_dt.api.analysis import retrieve_analysis
from owasp_dt.api.finding import get_findings_by_project
from owasp_dt.api.project import get_projects
from owasp_dt.models.get_findings_by_project_source import GetFindingsByProjectSource
from owasp_dt.types import UNSET
from test import api, base_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Show analysis details for findings (uses test/test.env for credentials).",
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
    # Filtering options (same as list_findings)
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
    # Analysis-specific filters
    parser.add_argument(
        "--state",
        dest="analysis_states",
        help="Filter by analysis state (comma-separated, e.g., IN_TRIAGE,EXPLOITABLE). "
             "Valid states: EXPLOITABLE, FALSE_POSITIVE, IN_TRIAGE, NOT_AFFECTED, NOT_SET, RESOLVED",
    )
    parser.add_argument(
        "--only-analyzed",
        action="store_true",
        help="Only show findings that have been analyzed (state != NOT_SET).",
    )
    parser.add_argument(
        "--only-unanalyzed",
        action="store_true",
        help="Only show findings that have NOT been analyzed (state == NOT_SET or no analysis).",
    )
    parser.add_argument(
        "--fetch-details",
        action="store_true",
        help="Fetch full analysis details including comments (slower, makes additional API calls).",
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


def matches_pattern(value: str | None, patterns: list[str] | None) -> bool:
    """Check if value matches any of the patterns (supports wildcards)."""
    if not patterns:
        return True
    if not value:
        return False
    value_lower = value.lower()
    for pattern in patterns:
        pattern_lower = pattern.lower()
        if fnmatch.fnmatch(value_lower, pattern_lower):
            return True
        if value_lower == pattern_lower:
            return True
    return False


def matches_uuid(value: str | None, uuids: list[str] | None) -> bool:
    """Check if value matches any of the UUIDs (exact match, case-insensitive)."""
    if not uuids:
        return True
    if not value:
        return False
    value_lower = value.lower()
    return any(u.lower() == value_lower for u in uuids)


def matches_severity(severity: str | None, severities: list[str] | None) -> bool:
    """Check if severity matches any of the allowed severities."""
    if not severities:
        return True
    if not severity:
        return False
    return severity.upper() in [s.upper() for s in severities]


def matches_analysis_state(state: str | None, states: list[str] | None) -> bool:
    """Check if analysis state matches any of the allowed states."""
    if not states:
        return True
    if not state:
        return False
    return state.upper() in [s.upper() for s in states]


def filter_finding(finding, args: argparse.Namespace) -> bool:
    """Return True if finding passes all filters."""
    vuln = getattr(finding, "vulnerability", None)
    component = getattr(finding, "component", None)
    analysis = getattr(finding, "analysis", None)
    
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
    
    # Get analysis state
    analysis_state = None
    if analysis and not isinstance(analysis, type(UNSET)):
        state_obj = getattr(analysis, "state", None)
        if state_obj and not isinstance(state_obj, type(UNSET)):
            analysis_state = str(state_obj)
    
    # Filter by analysis state
    if args.analysis_states:
        state_list = args.analysis_states.split(",")
        if not matches_analysis_state(analysis_state, state_list):
            return False
    
    # Filter for only analyzed
    if args.only_analyzed:
        if not analysis_state or analysis_state == "NOT_SET":
            return False
    
    # Filter for only unanalyzed
    if args.only_unanalyzed:
        if analysis_state and analysis_state != "NOT_SET":
            return False
    
    return True


def filter_project(project, args: argparse.Namespace) -> bool:
    """Return True if project passes filters."""
    if not matches_uuid(project.uuid, args.project_ids):
        return False
    if not matches_pattern(project.name, args.project_names):
        return False
    return True


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


def format_timestamp(timestamp_ms: int) -> str:
    """Format UNIX epoch milliseconds as human-readable date."""
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def get_analysis_state_emoji(state: str | None) -> str:
    """Get emoji for analysis state."""
    if not state:
        return "❓"
    state_emojis = {
        "EXPLOITABLE": "🔴",
        "FALSE_POSITIVE": "✅",
        "IN_TRIAGE": "🔍",
        "NOT_AFFECTED": "🟢",
        "NOT_SET": "⚪",
        "RESOLVED": "✔️",
    }
    return state_emojis.get(state.upper(), "❓")


def show_analysis(client, args: argparse.Namespace) -> None:
    total_projects = 0
    total_findings = 0
    matched_findings = 0
    
    # Count by analysis state
    state_counts: dict[str, int] = {}
    
    # Parse filters
    severity_list = args.severities.split(",") if args.severities else None
    state_list = args.analysis_states.split(",") if args.analysis_states else None
    
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
    if state_list:
        filters_active.append(f"Analysis states: {', '.join(state_list)}")
    if args.only_analyzed:
        filters_active.append("Only analyzed findings")
    if args.only_unanalyzed:
        filters_active.append("Only unanalyzed findings")
    
    if filters_active:
        print("Active filters:")
        for f in filters_active:
            print(f"  • {f}")
        print()

    for project in iter_projects(client, args.page_size):
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
        
        if not filtered_findings:
            if filters_active:
                continue
        
        print(f"Project: {project.name} ({project.uuid}) — {len(filtered_findings)} findings")
        
        if args.count_only:
            # Still count states for summary
            for finding in filtered_findings:
                analysis = getattr(finding, "analysis", None)
                state = "NOT_SET"
                if analysis and not isinstance(analysis, type(UNSET)):
                    state_obj = getattr(analysis, "state", None)
                    if state_obj and not isinstance(state_obj, type(UNSET)):
                        state = str(state_obj)
                state_counts[state] = state_counts.get(state, 0) + 1
            continue
            
        for finding in filtered_findings:
            vuln = getattr(finding, "vulnerability", None)
            vuln_id = getattr(vuln, "vuln_id", None) if vuln else None
            vuln_uuid = getattr(vuln, "uuid", None) if vuln else None
            component = getattr(finding, "component", None)
            component_name = getattr(component, "name", None) if component else None
            component_version = getattr(component, "version", None) if component else None
            component_uuid = getattr(component, "uuid", None) if component else None
            severity = getattr(vuln, "severity", None) if vuln else None
            
            # Get basic analysis from finding
            analysis = getattr(finding, "analysis", None)
            analysis_state = "NOT_SET"
            is_suppressed = False
            
            if analysis and not isinstance(analysis, type(UNSET)):
                state_obj = getattr(analysis, "state", None)
                if state_obj and not isinstance(state_obj, type(UNSET)):
                    analysis_state = str(state_obj)
                supp = getattr(analysis, "is_suppressed", None)
                if supp and not isinstance(supp, type(UNSET)):
                    is_suppressed = supp
            
            # Count states
            state_counts[analysis_state] = state_counts.get(analysis_state, 0) + 1
            
            comp_str = f"{component_name}@{component_version}" if component_version else (component_name or 'unknown')
            state_emoji = get_analysis_state_emoji(analysis_state)
            suppressed_str = " [SUPPRESSED]" if is_suppressed else ""
            
            print(
                f"  {state_emoji} {vuln_id or 'unknown'} | {comp_str} | "
                f"severity={severity or 'unknown'} | state={analysis_state}{suppressed_str}"
            )
            
            # Fetch detailed analysis if requested
            if args.fetch_details and component_uuid and vuln_uuid:
                try:
                    detail_resp = retrieve_analysis.sync_detailed(
                        client=client,
                        project=UUID(project.uuid),
                        component=UUID(component_uuid),
                        vulnerability=UUID(vuln_uuid),
                    )
                    if detail_resp.status_code == 200 and detail_resp.parsed:
                        detail = detail_resp.parsed
                        
                        # Show justification
                        justification = getattr(detail, "analysis_justification", None)
                        if justification and not isinstance(justification, type(UNSET)):
                            print(f"      Justification: {justification}")
                        
                        # Show response
                        response = getattr(detail, "analysis_response", None)
                        if response and not isinstance(response, type(UNSET)):
                            print(f"      Response: {response}")
                        
                        # Show details
                        details = getattr(detail, "analysis_details", None)
                        if details and not isinstance(details, type(UNSET)):
                            print(f"      Details: {details}")
                        
                        # Show comments
                        comments = getattr(detail, "analysis_comments", None)
                        if comments and not isinstance(comments, type(UNSET)) and comments:
                            print(f"      Comments ({len(comments)}):")
                            for comment in comments:
                                ts = format_timestamp(comment.timestamp)
                                commenter = getattr(comment, "commenter", "unknown")
                                if isinstance(commenter, type(UNSET)):
                                    commenter = "unknown"
                                print(f"        [{ts}] {commenter}: {comment.comment}")
                except Exception as e:
                    print(f"      (Failed to fetch details: {e})", file=sys.stderr)

    # Print summary
    print(f"\n{'='*80}")
    print("Summary:")
    print(f"  Projects queried: {total_projects}")
    print(f"  Total findings: {total_findings}")
    print(f"  Matched findings: {matched_findings}")
    
    if state_counts:
        print("\nAnalysis State Distribution:")
        for state in ["NOT_SET", "IN_TRIAGE", "EXPLOITABLE", "NOT_AFFECTED", "FALSE_POSITIVE", "RESOLVED"]:
            count = state_counts.get(state, 0)
            if count > 0:
                emoji = get_analysis_state_emoji(state)
                pct = (count / matched_findings * 100) if matched_findings > 0 else 0
                print(f"  {emoji} {state}: {count} ({pct:.1f}%)")


def main() -> int:
    args = parse_args()
    load_env()
    client = api.create_client_from_env()
    show_analysis(client, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

