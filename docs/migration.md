# Migration Guide: Vunnel (Python) to vulnz (Go)

## Overview

vulnz-go is a Go port of [Vunnel](https://github.com/anchore/vunnel), the vulnerability data aggregator from Anchore. It collects, transforms, and stores vulnerability information from OS distributions, language ecosystems, and security databases into a unified format.

### What is the same

- Same JSON output schema (capitalized field names for backwards compatibility)
- Same flat-file and SQLite storage backends
- Same workspace directory structure
- Same provider concept (fetch, transform, store)
- Same per-host rate limiting and retry behavior
- Same xxHash64 file integrity checksums

### What is different

- Language: Python -> Go (single static binary, no runtime dependencies)
- Build system: pip/poetry -> Go modules
- Configuration file: `runtime.yaml` -> `~/.vulnz.yaml`
- CLI interface: `vunnel` -> `vulnz`
- Logging: Python logging -> structured slog
- Provider registration: Python class discovery -> Go init() + factory pattern
- No Python virtual environment required

---

## Configuration Differences

### Config file location

| Vunnel (Python) | vulnz (Go) |
|---|---|
| `runtime.yaml` (project root or specified path) | `~/.vulnz.yaml` or `./.vulnz.yaml` |
| `--runtime` flag | `--workspace` flag (or `-w`) |
| `--config` flag | `--config` flag (or `-c`) |

### Config file format

Vunnel uses `runtime.yaml`:

```yaml
runtime:
  workspace: ./workspace
  results:
    existing_results: delete-before-write
    result_store: sqlite

providers:
  alpine:
    runtime:
      result_store: sqlite
```

vulnz-go uses `~/.vulnz.yaml`:

```yaml
log:
  level: info
  verbose: false

executor:
  max_concurrent: 4
  timeout: 2h

providers:
  alpine:
    runtime:
      result_store: sqlite
      existing_results: delete-before-write
```

### Environment variables

| Vunnel (Python) | vulnz (Go) | Purpose |
|---|---|---|
| `NVD_API_KEY` | `NVD_API_KEY` | NVD API key for rate limit bypass |
| (none) | `VULNZ_LOG_LEVEL` | Log level override |
| (none) | `VULNZ_LOG_VERBOSE` | Verbose logging |

Environment variables use the `VULNZ_` prefix and are mapped to config keys:

```bash
# Vunnel
export NVD_API_KEY=your-key

# vulnz-go (same NVD key)
export NVD_API_KEY=your-key

# vulnz-go specific
export VULNZ_LOG_LEVEL=debug
export VULNZ_EXECUTOR_MAX_CONCURRENT=8
```

---

## Provider Differences

All Vunnel providers have been ported to Go. Providers that previously used separate OVAL or CSAF parsers in Python now share common Go implementations.

### Ported features

- All 28 Vunnel providers available
- OVAL and CSAF parsing (shared implementations across providers)
- Flat-file and SQLite storage backends
- Incremental update support via `lastUpdated` parameter
- Per-host rate limiting and exponential backoff with jitter

### Not yet ported

- **fixdate integration** -- the fixdate provider for tracking fix availability dates is not yet available
- **NVD override synthesis** -- the post-processing step that synthesizes NVD CVSS data into other providers is not yet implemented
- **Ubuntu EOL git history traversal** -- simplified to a straightforward git clone approach rather than the more complex history traversal used in Python

### Provider registration

Vunnel (Python) uses class-based discovery:

```python
# vunnel/providers/alpine/__init__.py
from vunnel.providers.alpine import Provider

# Discovered automatically via entry points or import
```

vulnz (Go) uses init-based factory registration:

```go
// internal/providers/alpine/alpine.go
package alpine

import "github.com/shift/vulnz/internal/provider"

func init() {
    provider.Register("alpine", NewAlpineProvider)
}
```

---

## Output Format

### JSON schema

The output JSON schema is identical to Vunnel. Field names are capitalized for backwards compatibility:

```json
{
  "Vulnerability": {
    "Name": "CVE-2023-1234",
    "NamespaceName": "alpine:3.19",
    "Description": "A vulnerability in...",
    "Severity": "High",
    "Link": "https://...",
    "CVSS": [
      {
        "version": "3.1",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_metrics": {
          "base_score": 9.8,
          "exploitability_score": 3.9,
          "impact_score": 5.9,
          "base_severity": "CRITICAL"
        },
        "status": "verified"
      }
    ],
    "FixedIn": [
      {
        "Name": "pkg-name",
        "NamespaceName": "alpine:3.19",
        "VersionFormat": "apk",
        "Version": "1.2.3-r0"
      }
    ],
    "Metadata": {}
  }
}
```

### Storage backends

| Backend | Path | Description |
|---|---|---|
| flat-file | `./data/<provider>/storage/<namespace>/<vuln-id>.json` | One JSON file per vulnerability |
| sqlite | `./data/<provider>/storage/results.db` | SQLite database with batch inserts (default batch: 5000) |

### Workspace layout

The workspace structure is the same as Vunnel:

```
data/
  alpine/
    metadata.json
    checksums
    input/
      secdb.json
    results/
      storage/
  ubuntu/
    metadata.json
    ...
```

---

## CLI Comparison

### Command mapping

| Vunnel (Python) | vulnz (Go) | Description |
|---|---|---|
| `vunnel sync -p alpine` | `vulnz run alpine` | Run a single provider |
| `vunnel sync -p alpine,debian` | `vulnz run alpine debian` | Run multiple providers |
| `vunnel sync -a` | `vulnz run --all` | Run all providers |
| `vunnel list` | `vulnz list` | List available providers |
| `vunnel schema` | N/A | Schema is embedded in Go types |
| (none) | `vulnz config show` | Show current configuration |
| (none) | `vulnz config validate` | Validate config file |
| (none) | `vulnz status` | Show provider status |
| (none) | `vulnz clear` | Clear workspace data |
| (none) | `vulnz version` | Show version info |

### Flag mapping

| Vunnel flag | vulnz-go flag | Description |
|---|---|---|
| `-p <provider>` | positional arg or `--provider` / `-p` | Provider name(s) |
| `-a` | `--all` / `-a` | Run all providers |
| `--runtime <path>` | `--workspace <path>` / `-w` | Workspace directory |
| `--config <path>` | `--config <path>` / `-c` | Config file path |
| (none) | `--parallel <n>` | Max parallel providers (default: 4) |
| (none) | `--since <timestamp>` | Only fetch data since timestamp |
| (none) | `--log-level <level>` | Log level |
| (none) | `--output <format>` | Output format: text, json |
| (none) | `--tags <tags>` | Filter providers by tags |

### Common examples

```bash
# Vunnel
vunnel sync -p alpine
vunnel sync -a --runtime ./workspace
vunnel list

# vulnz-go (equivalent)
vulnz run alpine
vulnz run --all --workspace ./workspace
vulnz list
```

```bash
# vulnz-go specific features
vulnz run --all --parallel 8                # Parallel execution
vulnz run alpine --since 2024-03-01T00:00:00Z  # Incremental updates
vulnz list --tags os,linux                  # Filter by tags
vulnz run --all --output json               # JSON output
vulnz config show                           # Show configuration
```

---

## Building and Running

### Vunnel (Python)

```bash
pip install vunnel
vunnel sync -p alpine
```

### vulnz (Go)

```bash
git clone https://github.com/shift/vulnz.git
cd vulnz
go build -o vulnz ./cmd/vulnz
./vulnz run alpine
```

Or install directly:

```bash
go install github.com/shift/vulnz/cmd/vulnz@latest
vulnz run alpine
```

### Key advantages of the Go version

- Single static binary, no Python runtime or virtual environment
- Faster execution (compiled, no interpreter overhead)
- Built-in concurrency via goroutines and semaphore-based parallel execution
- Per-host connection pooling with dedicated transports
- Atomic state writes via temp file + rename
- No dependency management complexity (Go modules)
