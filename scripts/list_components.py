#!/usr/bin/env python3
"""List every component across all projects in the configured Dependency-Track instance."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

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

from owasp_dt.api.component import get_all_components
from owasp_dt.api.project import get_projects
from owasp_dt.types import UNSET
from test import api, base_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="List components for every project (credentials from test/test.env).",
    )
    parser.add_argument(
        "--project-page-size",
        type=int,
        default=100,
        help="Number of projects to request per page (default: 100).",
    )
    parser.add_argument(
        "--component-page-size",
        type=int,
        default=100,
        help="Number of components to request per page (default: 100).",
    )
    parser.add_argument(
        "--only-outdated",
        action="store_true",
        help="Only return components with outdated versions.",
    )
    parser.add_argument(
        "--only-direct",
        action="store_true",
        help="Restrict to direct components only.",
    )
    return parser.parse_args()


def load_env() -> None:
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def iter_projects(client, page_size: int):
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


def iter_components(client, project_uuid, page_size: int, only_outdated: bool, only_direct: bool):
    page_number = 1
    only_outdated_param = True if only_outdated else UNSET
    only_direct_param = True if only_direct else UNSET
    while True:
        resp = get_all_components.sync_detailed(
            client=client,
            uuid=project_uuid,
            page_number=str(page_number),
            page_size=str(page_size),
            only_outdated=only_outdated_param,
            only_direct=only_direct_param,
        )
        if resp.status_code != 200:
            print(
                f"[WARN] Failed to fetch components for project {project_uuid} on page {page_number}: "
                f"status {resp.status_code}",
                file=sys.stderr,
            )
            return
        components = resp.parsed or []
        if not components:
            break
        for component in components:
            yield component
        page_number += 1


def list_components(client, args: argparse.Namespace) -> None:
    total_projects = 0
    total_components = 0

    for project in iter_projects(client, args.project_page_size):
        total_projects += 1
        project_components = list(
            iter_components(
                client,
                project.uuid,
                args.component_page_size,
                args.only_outdated,
                args.only_direct,
            ),
        )
        total_components += len(project_components)
        print(f"Project: {project.name} ({project.uuid}) — {len(project_components)} component(s)")
        for component in project_components:
            version = component.version or "unknown"
            purl = component.purl or "n/a"
            print(f"  - {component.name} {version} | purl={purl}")

    print(f"\nQueried {total_projects} project(s) and {total_components} component(s).")


def main() -> int:
    args = parse_args()
    load_env()
    client = api.create_client_from_env()
    list_components(client, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

