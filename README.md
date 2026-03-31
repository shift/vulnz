# vulnz

vulnz collects, transforms, and stores vulnerability data from 28 providers (NVD, OS distributions, EU regulatory bodies, exploit databases) into a unified JSON schema, with a focus on EU Cyber Resilience Act compliance.

## Vunnel vs vulnz (inspired by Vunnel)

| | Vunnel (Python) | vulnz |
|---|---|---|
| Language | Python 3.10+ | Go 1.25 |
| Distribution | pip package + Python runtime | Single static binary |
| Providers | 27 | 28 |
| Storage | SQLite only | Flat-file and SQLite |
| Concurrency | Process-based | Goroutine-based |
| HTTP client | requests | Per-host rate limiting, retry with backoff, connection pooling |
| Schema validation | Python classes | JSON Schema (programmatic) |
| EU CRA support | Partial | Full (KEV, EUVD, BSI CERT-Bund, CERT-FR, CISA ICS-CERT) |

## Installation

```bash
git clone https://github.com/shift/vulnz.git
cd vulnz
go build -o vulnz ./cmd/vulnz
```

Or with Make:

```bash
make build
```

## Quick Start

```bash
./vulnz list

./vulnz run kev

./vulnz run --all

./vulnz run --all --parallel 8
```

## CLI Reference

### Global Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config` | `-c` | `~/.vulnz.yaml` | Config file path |
| `--log-level` | `-l` | `info` | Log level (debug, info, warn, error) |
| `--verbose` | `-v` | `false` | Verbose output |
| `--output` | `-o` | `text` | Output format (text, json) |

### Commands

```
vulnz run [provider]     Run one or more providers
vulnz list               List registered providers
vulnz status [provider]  Show provider status and data freshness
vulnz clear [provider]   Clear provider workspace data
vulnz config show        Display current configuration
vulnz config validate    Validate configuration file
vulnz version            Show version, commit, and build info
```

### Run Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--all` | `-a` | `false` | Run all registered providers |
| `--provider` | `-p` | | Specific provider(s), comma-separated |
| `--workspace` | `-w` | `./data` | Workspace root directory |
| `--parallel` | | `4` | Max concurrent provider executions |
| `--since` | | | Only fetch data newer than timestamp (RFC3339) |

## Providers

| Provider | Description | Data Source |
|---|---|---|
| `kev` | Known Exploited Vulnerabilities | EUVD consolidated KEV dump |
| `euvd` | EU Vulnerability Database | ENISA exploited vulns API |
| `euvd-mapping` | CVE-EUVD ID mapping | ENISA mapping CSV |
| `nvd` | National Vulnerability Database | NVD CVE API 2.0 |
| `rhel` | Red Hat Enterprise Linux | CSAF 2.0 advisories |
| `ubuntu` | Ubuntu Security | CVE tracker git repo |
| `debian` | Debian Security | JSON + DSA text |
| `alpine` | Alpine Linux | secdb JSON |
| `amazon` | Amazon Linux | RSS XML + HTML |
| `oracle` | Oracle Linux | OVAL XML |
| `sles` | SUSE Linux Enterprise | OVAL XML |
| `mariner` | Azure Linux Mariner | OVAL XML |
| `rocky` | Rocky Linux | OSV API |
| `alma` | AlmaLinux | OSV git repo |
| `fedora` | Fedora | Bodhi REST API |
| `arch` | Arch Linux | JSON + ASA |
| `wolfi` | Wolfi OS | secdb JSON |
| `chainguard` | Chainguard | secdb JSON |
| `chainguard-libraries` | Chainguard Libraries | OpenVEX JSON |
| `minimos` | Minimos | secdb JSON |
| `bitnami` | Bitnami | vulndb git repo |
| `bsi-cert-bund` | BSI CERT-Bund | CSAF 2.0 JSON |
| `cisa-ics-cert` | CISA ICS-CERT | CSAF 2.0 + GitHub API |
| `cert-fr` | CERT-FR (ANSSI) | RSS XML + HTML |
| `epss` | Exploit Prediction Scoring | EPSS CSV |
| `eol` | End of Life dates | endoflife.date API |
| `photon` | Photon OS | CVE JSON + wiki |
| `secureos` | SecureOS | secdb gzip + SHA256 |

## Architecture

```
cmd/vulnz/                  CLI entry point
internal/
  cli/                      Cobra command definitions
  provider/                 Provider framework (registry, executor, interfaces)
  providers/                Blank imports for provider registration
  storage/                  Flat-file and SQLite storage backends
  workspace/                Workspace management (locks, checksums, state)
  http/                     HTTP client with rate limiting, retry, backoff
  schema/                   JSON Schema validation
  utils/
    oval/                   OVAL XML parser
    csaf/                   CSAF 2.0 parser
    rpm/                    RPM version comparison
    vulnerability/          Vulnerability type definitions
    archive/                Archive extraction utilities
    date/                   Date parsing helpers
```

Each provider implements the `Provider` interface, registers itself via `init()`, and is discovered at runtime through the provider registry. The executor runs providers concurrently with configurable parallelism and per-provider timeouts.

## Configuration

Config file: `~/.vulnz.yaml` (or `--config` flag). An example config is available at [`config.example.yaml`](config.example.yaml).

Configuration precedence: CLI flags > environment variables (`VULNZ_` prefix) > config file.

Key settings:

```yaml
log:
  level: info
root: ./data
executor:
  max_concurrent: 4
  timeout: 30m
providers:
  nvd:
    runtime:
      result_store: sqlite
      existing_results: delete-before-write
    api_key: "${NVD_API_KEY}"
```

Environment variable `NVD_API_KEY` is recommended for NVD API rate limit bypass.

## Output

Providers store results under `<workspace>/<provider>/storage/`. Each vulnerability is a JSON file following the standardised output schema.

## EU CRA Compliance

vulnz is specifically focused on EU Cyber Resilience Act compliance. Several providers carry data required for EU CRA:

- **KEV** -- `exploited_in_wild` flag with source attribution
- **EUVD** -- `exploitedSince` dates from ENISA
- **BSI CERT-Bund** -- German severity mapping, TR-03116 compliance fields
- **CERT-FR** -- ANSSI vulnerability tracking
- **CISA ICS-CERT** -- ICS advisory data

All EU-facing providers are tagged `eu-cra` and produce data in the standardised Vunnel vulnerability schema.

## Development

```bash
make test            Run tests with coverage
make lint            Run linters (go vet, go fmt, golangci-lint)
make clean           Remove build artifacts
make deps            Download and tidy dependencies
```

### Adding a Provider

1. Create `internal/provider/<name>/` with `provider.go` and `manager.go`
2. Implement the `Provider` interface
3. Register via blank import in `internal/providers/register.go`
4. Add tests in a `_suite_test.go` file (Ginkgo/Gomega)

## License

AGPL-3.0 -- see [LICENSE](LICENSE).

## Credits

Created by [shift](https://github.com/shift), inspired by [Vunnel](https://github.com/anchore/vunnel) by Anchore, Inc.
