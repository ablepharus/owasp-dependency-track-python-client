# Scripts

Command-line utilities for interacting with a Dependency-Track instance. All scripts use credentials from `test/test.env`.

## Setup

Ensure Dependency-Track is running:

```bash
docker-compose -f test/docker-compose.yml up -d
```

Scripts automatically load configuration from `test/test.env`:

```env
DEPENDENCY_TRACK_BASE_URL=http://localhost:8081
DEPENDENCY_TRACK_API_KEY=your-api-key
```

## Scripts Overview

| Script | Purpose |
|--------|---------|
| `upload_sbom` | Upload an SBOM file to a project |
| `enable_vulnerability_sources.py` | Enable NVD, OSV, GitHub Advisories |
| `force_vuln_sync.py` | Force immediate vulnerability database sync |
| `wait_for_vuln_data.py` | Wait for vulnerability database to populate |
| `trigger_analysis.py` | Trigger vulnerability analysis for projects |
| `analyze_and_wait.py` | Trigger analysis and wait for completion |
| `list_findings.py` | List all findings with filtering |
| `list_vulnerabilities.py` | List HIGH/CRITICAL vulnerabilities by age |
| `list_components.py` | List all components across projects |
| `show_analysis.py` | Show analysis state and details for findings |

---

## SBOM Upload

### `upload_sbom`

Upload a CycloneDX SBOM to Dependency-Track.

```bash
./scripts/upload_sbom examples/debian-bookworm-sbom.json
./scripts/upload_sbom examples/ubuntu1804-base-sbom.json --project ubuntu1804-base
```

**Options:**
- First argument: Path to SBOM file (required)
- `--project NAME`: Project name (defaults to filename without extension)

---

## Vulnerability Sources

### `enable_vulnerability_sources.py`

Enable vulnerability sources (NVD, OSV, GitHub Advisories) via the Dependency-Track API.

```bash
python scripts/enable_vulnerability_sources.py
```

Run this after starting Dependency-Track to enable vulnerability matching.

### `force_vuln_sync.py`

Check vulnerability source status and force an immediate NVD sync.

```bash
python scripts/force_vuln_sync.py
```

**Output:**
- Shows which vulnerability sources are enabled
- Sets NVD sync cadence to 1 hour to trigger immediate download

### `wait_for_vuln_data.py`

Poll the vulnerability database until data becomes available.

```bash
python scripts/wait_for_vuln_data.py
python scripts/wait_for_vuln_data.py --timeout 3600 --interval 60
```

**Options:**
- `--timeout SECONDS`: Maximum wait time (default: 1800 = 30 min)
- `--interval SECONDS`: Poll interval (default: 30)

---

## Analysis

### `trigger_analysis.py`

Trigger vulnerability analysis for one or more projects.

```bash
# Analyze specific project by name
python scripts/trigger_analysis.py --project-name ubuntu1804-base

# Analyze by UUID
python scripts/trigger_analysis.py --project-uuid 786b5b18-52f5-459f-8fce-b2a0423a50aa

# Analyze all projects
python scripts/trigger_analysis.py --all-projects
```

**Options:**
- `--project-name NAME`: Project name (repeatable)
- `--project-uuid UUID`: Project UUID (repeatable)
- `--all-projects`: Analyze every accessible project

### `analyze_and_wait.py`

Trigger analysis for all projects and wait for completion.

```bash
python scripts/analyze_and_wait.py
```

Polls each analysis job until complete (timeout: 180s per job).

---

## Querying Findings

### `list_findings.py`

List all findings across projects with comprehensive filtering.

```bash
# List all findings
python scripts/list_findings.py

# Filter by severity
python scripts/list_findings.py --severity HIGH,CRITICAL

# Filter by CVE (wildcards supported)
python scripts/list_findings.py --cve-id "CVE-2023-*"

# Filter by component name (wildcards supported)
python scripts/list_findings.py --component-name "openssl*"

# Filter by project
python scripts/list_findings.py --project-name "ubuntu*"

# Combine filters
python scripts/list_findings.py --severity CRITICAL --component-name "curl*" --count-only
```

**Filter Options:**
- `--cve-id CVE`: Filter by CVE ID (repeatable, wildcards: `CVE-2023-*`)
- `--project-id UUID`: Filter by project UUID (repeatable)
- `--project-name NAME`: Filter by project name (repeatable, wildcards: `ubuntu*`)
- `--component-id UUID`: Filter by component UUID (repeatable)
- `--component-name NAME`: Filter by component name (repeatable, wildcards: `openssl*`)
- `--severity LEVELS`: Comma-separated severity levels (`HIGH,CRITICAL`)

**Other Options:**
- `--include-suppressed`: Include suppressed findings
- `--source SOURCE`: Filter by finding source
- `--count-only`: Only show counts, not individual findings
- `--page-size N`: Pagination size (default: 100)

### `list_vulnerabilities.py`

List HIGH/CRITICAL vulnerabilities older than N days.

```bash
# HIGH/CRITICAL vulnerabilities older than 7 days
python scripts/list_vulnerabilities.py

# All HIGH/CRITICAL (no age filter)
python scripts/list_vulnerabilities.py --days 0

# Older than 30 days
python scripts/list_vulnerabilities.py --days 30
```

**Options:**
- `--days N`: Minimum age in days (default: 7, use 0 for all)
- `--include-suppressed`: Include suppressed findings
- `--source SOURCE`: Filter by finding source
- `--page-size N`: Pagination size (default: 100)

### `show_analysis.py`

Show analysis state and details for findings. Accepts all `list_findings.py` filters plus analysis-specific options.

```bash
# Show all findings with analysis state
python scripts/show_analysis.py

# Filter by analysis state
python scripts/show_analysis.py --state IN_TRIAGE,EXPLOITABLE

# Show only unanalyzed findings
python scripts/show_analysis.py --only-unanalyzed --severity CRITICAL

# Show only analyzed findings
python scripts/show_analysis.py --only-analyzed

# Fetch full analysis details (comments, justification, etc.)
python scripts/show_analysis.py --cve-id CVE-2023-38408 --fetch-details

# Summary counts only
python scripts/show_analysis.py --count-only
```

**Analysis States:** `EXPLOITABLE`, `FALSE_POSITIVE`, `IN_TRIAGE`, `NOT_AFFECTED`, `NOT_SET`, `RESOLVED`

**Analysis-Specific Options:**
- `--state STATES`: Filter by analysis state (comma-separated)
- `--only-analyzed`: Only show findings with analysis (state ≠ NOT_SET)
- `--only-unanalyzed`: Only show findings without analysis
- `--fetch-details`: Fetch full analysis including comments (slower)

**Output includes:**
- Emoji indicators: 🔴 EXPLOITABLE, ✅ FALSE_POSITIVE, 🔍 IN_TRIAGE, 🟢 NOT_AFFECTED, ⚪ NOT_SET, ✔️ RESOLVED
- Suppression status
- Summary with state distribution percentages

---

## Components

### `list_components.py`

List all components across all projects.

```bash
python scripts/list_components.py
python scripts/list_components.py --page-size 200
```

**Options:**
- `--page-size N`: Pagination size (default: 100)

---

## Typical Workflow

```bash
# 1. Start Dependency-Track
docker-compose -f test/docker-compose.yml up -d

# 2. Enable vulnerability sources
python scripts/enable_vulnerability_sources.py

# 3. Upload SBOMs
./scripts/upload_sbom examples/ubuntu1804-base-sbom.json

# 4. Wait for vulnerability database (first run only, ~10-30 min)
python scripts/wait_for_vuln_data.py

# 5. Trigger analysis
python scripts/analyze_and_wait.py

# 6. Query results
python scripts/list_findings.py --severity HIGH,CRITICAL
python scripts/list_vulnerabilities.py --days 7
python scripts/show_analysis.py --only-unanalyzed --severity CRITICAL
```

