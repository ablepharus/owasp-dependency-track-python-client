#!/usr/bin/env python3
"""Force an immediate vulnerability database sync and check status."""

from __future__ import annotations

import os
import sys
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

from owasp_dt.api.config_property import update_config_property, get_config_properties
from owasp_dt.models import ConfigProperty, ConfigPropertyPropertyType
from test import api, base_dir


def load_env() -> None:
    """Load environment variables from test.env."""
    env_path = base_dir / "test.env"
    if env_path.exists():
        load_dotenv(env_path)


def check_vuln_sources(client):
    """Check which vulnerability sources are enabled."""
    print("Checking vulnerability source configuration...")
    resp = get_config_properties.sync_detailed(client=client)
    
    if resp.status_code != 200:
        print(f"Failed to get config properties: {resp.status_code}")
        return
    
    props = resp.parsed or []
    vuln_sources = [p for p in props if p.group_name == "vuln-source"]
    
    print("\nVulnerability Sources:")
    for prop in vuln_sources:
        if prop.property_name and prop.property_name.endswith('.enabled'):
            source_name = prop.property_name.replace('.enabled', '')
            status = "✔ ENABLED" if prop.property_value == "true" else "✗ disabled"
            print(f"  {source_name}: {status}")


def force_sync(client):
    """Force immediate NVD mirror sync by setting cadence to 1 hour."""
    print("\nForcing NVD sync...")
    
    # Set cadence to trigger sync
    prop = ConfigProperty(
        group_name="task-scheduler",
        property_name="nist.mirror.cadence",
        property_value="1",
        property_type=ConfigPropertyPropertyType.NUMBER,
    )
    resp = update_config_property.sync_detailed(client=client, body=prop)
    
    if resp.status_code == 200:
        print("✔ NVD sync cadence set to 1 hour")
        print("\nNOTE: The NVD mirror download is a background task.")
        print("It may take 10-30 minutes to download the full NVD database.")
        print("Check the Dependency-Track logs or Administration → Analyzers")
        print("to monitor progress.")
    else:
        print(f"✗ Failed to update sync cadence: {resp.status_code}")


def main() -> int:
    """Check and force vulnerability database sync."""
    load_env()
    client = api.create_client_from_env()
    
    check_vuln_sources(client)
    force_sync(client)
    
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

