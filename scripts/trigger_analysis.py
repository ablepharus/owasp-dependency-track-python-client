#!/usr/bin/env python3
"""Trigger Dependency-Track's vulnerability analysis for one or more projects."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable

try:
    from dotenv import load_dotenv  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
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

from owasp_dt.api.finding import analyze_project
from owasp_dt.api.project import get_projects
from test import api, base_dir, project_name as default_project_name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trigger analysis for the specified projects (credentials from test/test.env).",
    )
    parser.add_argument(
        "--project-uuid",
        action="append",
        help="Project UUID to analyze (can be repeated).",
    )
    parser.add_argument(
        "--project-name",
        action="append",
        help="Project name to analyze (can be repeated; resolves via /v1/project?name=...).",
    )
    parser.add_argument(
        "--all-projects",
        action="store_true",
        help="Analyze every project the API key can access.",
    )
    return parser.parse_args()


def load_env() -> None:
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def iter_projects(client, page_size: int = 200):
    page_number = 1
    while True:
        resp = get_projects.sync_detailed(
            client=client,
            page_number=str(page_number),
            page_size=str(page_size),
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Failed to fetch projects (page {page_number}): status {resp.status_code}",
            )
        projects = resp.parsed or []
        if not projects:
            break
        for project in projects:
            yield project
        page_number += 1


def resolve_projects_by_name(client, names: Iterable[str]):
    resolved = []
    for name in names:
        resp = get_projects.sync_detailed(client=client, name=name)
        projects = resp.parsed or []
        if not projects:
            raise SystemExit(f"No project found with name '{name}'")
        resolved.append(projects[0])
    return resolved


def trigger_analysis(client, project) -> None:
    print(f"Triggering analysis for {project.name} ({project.uuid}) ...", flush=True)
    resp = analyze_project.sync_detailed(client=client, uuid=project.uuid)
    if resp.status_code == 200:
        token = resp.parsed.token if resp.parsed else None
        if token:
            print(f"  ✔ Analysis request accepted (token={token})")
        else:
            print("  ✔ Analysis request accepted.")
    else:
        print(
            f"  ✖ Failed with status {resp.status_code}: {resp.content!r}",
            file=sys.stderr,
        )


def main() -> int:
    args = parse_args()
    load_env()
    client = api.create_client_from_env()

    targets = []
    if args.all_projects:
        targets = list(iter_projects(client))
    else:
        if not args.project_uuid and not args.project_name:
            args.project_name = [default_project_name]

        if args.project_uuid:
            uuid_map = {proj.uuid: proj for proj in iter_projects(client)}
            for uuid in args.project_uuid:
                project = uuid_map.get(uuid)
                if not project:
                    raise SystemExit(f"Project UUID not found: {uuid}")
                targets.append(project)

        if args.project_name:
            targets.extend(resolve_projects_by_name(client, args.project_name))

    if not targets:
        print("No projects resolved; nothing to analyze.", file=sys.stderr)
        return 1

    for project in targets:
        trigger_analysis(client, project)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

