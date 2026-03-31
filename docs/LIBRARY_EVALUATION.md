# Go Library Evaluation for vulnz-go

**Evaluation Date:** March 30, 2026  
**Evaluator:** 71-the-gopher (Go Expert Agent)  
**Project:** vulnz-go - Go port of Vunnel vulnerability aggregation tool

## Executive Summary

This document provides a comprehensive evaluation of critical Go libraries needed for the vulnz-go project. The evaluation focuses on maturity, maintenance status, community adoption, and suitability for parsing vulnerability data formats (OVAL, CSAF), querying GitHub Security Advisories, validating JSON schemas, building CLI interfaces, and testing.

### Key Recommendations

- ✅ **OVAL Parser:** Use `github.com/quay/goval-parser` with custom extensions
- ✅ **CSAF Parser:** Use `github.com/gocsaf/csaf/v3`
- ✅ **GraphQL Client:** Use `github.com/hasura/go-graphql-client`
- ✅ **JSON Schema Validator:** Use `github.com/santhosh-tekuri/jsonschema/v6`
- ✅ **CLI Framework:** Use `github.com/spf13/cobra`
- ✅ **Testing Framework:** Use `github.com/stretchr/testify` + stdlib

---

## 1. OVAL XML Parser

**Purpose:** Parse OVAL (Open Vulnerability and Assessment Language) XML documents for vulnerability definitions from Red Hat, Ubuntu, Debian, Oracle Linux, etc.

### Evaluation

#### Option A: github.com/quay/goval-parser ✅ RECOMMENDED

**GitHub:** https://github.com/quay/goval-parser  
**Import:** `github.com/quay/goval-parser/oval`  
**License:** BSD-2-Clause  
**Stars:** 7 | **Forks:** 10 | **Last Release:** v0.8.8 (Sep 2022)

**Pros:**
- Used by Quay (Red Hat's container registry) - production-proven
- Actively maintained fork of original ymomoi/goval-parser
- Clean API design with proper Go structs for OVAL definitions
- Imported by 22 other projects including Trivy, Clair
- BSD-2-Clause license is permissive
- Handles complex OVAL definitions and criteria logic

**Cons:**
- Last release was Sep 2022 (but OVAL spec is stable)
- Small community (7 stars)
- Documentation is minimal
- May need custom extensions for vendor-specific OVAL variants

**Maintenance Status:** 🟢 ACTIVE  
- Last commit: Sep 2022
- Used in production by major projects
- OVAL specification is stable (last update 2016)

**Recommendation:** ✅ **Use this library**

**Rationale:** Despite low GitHub stars, this is the most mature and production-tested OVAL parser in Go. It's used by Quay/Clair and Trivy, which are enterprise-grade vulnerability scanners. The OVAL specification is stable, so infrequent updates are expected.

---

#### Option B: Custom Implementation ⚠️ FALLBACK

**When to consider:**
- If quay/goval-parser doesn't support specific OVAL variants
- Need for vendor-specific extensions (e.g., SUSE, Alpine)
- Performance optimization for large OVAL files

**Approach:**
```go
// Use encoding/xml with custom structs
type OvalDefinitions struct {
    XMLName     xml.Name    `xml:"oval_definitions"`
    Generator   Generator   `xml:"generator"`
    Definitions Definitions `xml:"definitions"`
    Tests       Tests       `xml:"tests"`
    Objects     Objects     `xml:"objects"`
    States      States      `xml:"states"`
}
```

**Recommendation:** ⚠️ **Custom implementation as fallback**

---

## 2. CSAF Parser

**Purpose:** Parse CSAF (Common Security Advisory Framework) JSON documents from Red Hat, SUSE, Cisco, etc.

### Evaluation

#### Option A: github.com/gocsaf/csaf/v3 ✅ RECOMMENDED

**GitHub:** https://github.com/gocsaf/csaf  
**Import:** `github.com/gocsaf/csaf/v3/csaf`  
**License:** Apache-2.0  
**Stars:** 60 | **Forks:** 36 | **Last Release:** v3.5.1 (Dec 2025)

**Pros:**
- Official Go implementation from csaf.io community
- Full CSAF 2.0 specification support with errata
- Includes validator, downloader, uploader, aggregator tools
- Actively maintained (Dec 2025 release)
- Apache-2.0 license
- Used by 16 projects
- Comprehensive tooling ecosystem

**Cons:**
- Larger dependency footprint (includes full CSAF toolchain)
- May be over-featured if you only need parsing
- Documentation is tool-focused, less library-focused

**Maintenance Status:** 🟢 VERY ACTIVE  
- Last commit: Dec 2025
- Regular releases
- Active issue tracking (66 open issues)
- Community-driven development

**Recommendation:** ✅ **Use this library**

**Rationale:** This is the de-facto standard CSAF implementation in Go, maintained by the CSAF community. Active development, comprehensive specification support, and production use make it the clear choice.

---

#### Option B: github.com/openvex/go-vex/pkg/csaf

**GitHub:** https://github.com/openvex/go-vex  
**Import:** `github.com/openvex/go-vex/pkg/csaf`  
**License:** Apache-2.0  
**Stars:** Not tracked | **Imported by:** 4

**Pros:**
- Part of OpenVEX ecosystem
- Focuses on VEX (Vulnerability Exploitability eXchange)
- Lightweight

**Cons:**
- Less comprehensive than gocsaf
- Smaller community
- Focused on VEX use cases

**Recommendation:** ⚠️ **Consider if using OpenVEX stack**

---

## 3. GraphQL Client (GitHub Security Advisories API)

**Purpose:** Query GitHub Security Advisories GraphQL API for vulnerability data.

### Evaluation

#### Option A: github.com/hasura/go-graphql-client ✅ RECOMMENDED

**GitHub:** https://github.com/hasura/go-graphql-client  
**Import:** `github.com/hasura/go-graphql-client`  
**License:** MIT  
**Stars:** 470 | **Forks:** 100 | **Last Release:** v0.15.1 (Dec 2025)

**Pros:**
- Fork of shurcooL/graphql with extended features
- **Subscription support** (WebSocket)
- Named operations support
- Better error handling with retries
- Active maintenance (Dec 2025)
- Rich feature set:
  - Custom HTTP client
  - Request modifiers (auth injection)
  - Extensions binding
  - Raw response access
- Good documentation with examples

**Cons:**
- API changed in v0.8.0 (breaking change from *json.RawMessage to []byte)
- Some GitHub-specific features may not be needed
- Slightly larger API surface

**Maintenance Status:** 🟢 VERY ACTIVE  
- Last release: Dec 2025
- Regular maintenance
- Responsive to issues

**Recommendation:** ✅ **Use this library**

**Rationale:** Most feature-rich and actively maintained GraphQL client. The subscription support and retry logic will be valuable for production use. Better error handling than alternatives.

**Example Usage:**
```go
client := graphql.NewClient("https://api.github.com/graphql", httpClient).
    WithRequestModifier(func(r *http.Request) {
        r.Header.Set("Authorization", "Bearer "+token)
    }).
    WithRetry(3).
    WithRetryBaseDelay(time.Second)

var query struct {
    SecurityAdvisories struct {
        Nodes []struct {
            GHSA      string
            Summary   string
            Severity  string
            UpdatedAt time.Time
        }
    } `graphql:"securityAdvisories(first: 100, after: $cursor)"`
}

err := client.Query(context.Background(), &query, map[string]interface{}{
    "cursor": nil,
})
```

---

#### Option B: github.com/shurcooL/graphql

**GitHub:** https://github.com/shurcooL/graphql  
**Import:** `github.com/shurcooL/graphql`  
**License:** MIT  
**Stars:** 729 | **Forks:** 287

**Pros:**
- Original library, stable API
- Used by GitHub's own githubv4 package
- Minimalist design
- Well-tested

**Cons:**
- Less feature-rich (no subscriptions, limited retry)
- Less active maintenance
- Fewer convenience features

**Recommendation:** ⚠️ **Use if you need stable, minimal API**

---

#### Option C: github.com/machinebox/graphql

**GitHub:** https://github.com/machinebox/graphql  
**Import:** `github.com/machinebox/graphql`  
**License:** Apache-2.0  
**Stars:** 963 | **Forks:** 218

**Pros:**
- Low-level HTTP-focused design
- Simple API
- Multipart form data support (file uploads)

**Cons:**
- Less idiomatic Go (no struct-based queries)
- More manual request building
- Not designed for complex GraphQL schemas

**Recommendation:** ❌ **Avoid for GitHub API**

**Rationale:** Too low-level for GitHub's complex GraphQL schema. Prefer struct-based query builders.

---

## 4. JSON Schema Validator

**Purpose:** Validate vulnerability data against JSON Schema (draft-07 minimum).

### Evaluation

#### Option A: github.com/santhosh-tekuri/jsonschema/v6 ✅ RECOMMENDED

**GitHub:** https://github.com/santhosh-tekuri/jsonschema  
**Import:** `github.com/santhosh-tekuri/jsonschema/v6`  
**License:** Apache-2.0  
**Stars:** 1,200 | **Imported by:** 230 | **Last Release:** v6.0.2 (May 2025)

**Pros:**
- **Supports draft 2020-12, 2019-09, draft-7, draft-6, draft-4**
- Passes full JSON-Schema-Test-Suite
- Excellent performance (optimized for large datasets)
- Vocabulary-based validation
- Custom format registration
- Content assertions (base64, contentMediaType, contentSchema)
- Rich error output (hierarchical, detailed)
- Active maintenance (May 2025)
- CLI tool included (`jv`)
- Comprehensive documentation

**Cons:**
- v6 is major version (API may change)
- Larger API surface than simpler validators

**Maintenance Status:** 🟢 VERY ACTIVE  
- Last release: May 2025
- Regular updates
- Full test suite compliance
- Responsive maintainer

**Recommendation:** ✅ **Use this library**

**Rationale:** Most comprehensive and performant JSON Schema validator in Go. Full draft support, excellent error messages, and proven performance make it ideal for validating large vulnerability datasets.

**Example Usage:**
```go
import "github.com/santhosh-tekuri/jsonschema/v6"

compiler := jsonschema.NewCompiler()
compiler.Draft = jsonschema.Draft7

schema, err := compiler.Compile("schema.json")
if err != nil {
    return err
}

var data interface{}
json.Unmarshal(jsonData, &data)

if err := schema.Validate(data); err != nil {
    return fmt.Errorf("validation failed: %w", err)
}
```

---

#### Option B: github.com/xeipuuv/gojsonschema

**GitHub:** https://github.com/xeipuuv/gojsonschema  
**Import:** `github.com/xeipuuv/gojsonschema`  
**License:** Apache-2.0  
**Stars:** 2,700 | **Forks:** 369

**Pros:**
- Very popular (2.7k stars)
- Supports draft-04, draft-06, draft-07
- Simple API
- Good documentation

**Cons:**
- **Last release: Oct 2019** (over 6 years old)
- No draft 2019-09 or 2020-12 support
- Slower performance than santhosh-tekuri
- Maintenance unclear (108 open issues)

**Recommendation:** ⚠️ **Avoid due to age**

**Rationale:** While popular, the lack of updates since 2019 and missing draft 2019-09/2020-12 support makes it unsuitable for modern JSON Schema validation.

---

#### Option C: github.com/qri-io/jsonschema

**GitHub:** https://github.com/qri-io/jsonschema  
**Import:** `github.com/qri-io/jsonschema`  
**License:** MIT  
**Stars:** 139 | **Last Release:** v0.2.1 (Mar 2021)

**Pros:**
- Clean API
- MIT license

**Cons:**
- Less comprehensive than alternatives
- Older (2021)
- Smaller community

**Recommendation:** ⚠️ **Consider only if MIT license required**

---

## 5. CLI Framework

**Purpose:** Build Vunnel-compatible CLI with subcommands (run, list, clear, status, config).

### Evaluation

#### Option A: github.com/spf13/cobra ✅ RECOMMENDED

**GitHub:** https://github.com/spf13/cobra  
**Import:** `github.com/spf13/cobra`  
**License:** Apache-2.0  
**Stars:** 43,500 | **Forks:** 3,100 | **Last Release:** v1.10.2 (Dec 2025)

**Pros:**
- **Industry standard** (used by Kubernetes, Hugo, GitHub CLI, Docker)
- Excellent subcommand support
- POSIX-compliant flags
- Nested subcommands
- Global, local, and cascading flags
- Auto-generated help and usage
- Shell completion (bash, zsh, fish, powershell)
- Auto-generated man pages
- Command aliases
- Cobra generator for scaffolding
- Seamless Viper integration (config files)
- Massive ecosystem (43.5k stars, 204k imports)

**Cons:**
- Slightly verbose for simple CLIs
- Large API surface

**Maintenance Status:** 🟢 VERY ACTIVE  
- Last release: Dec 2025
- Maintained by spf13 (Hugo creator)
- Large contributor base
- Excellent documentation at cobra.dev

**Recommendation:** ✅ **Use this library**

**Rationale:** Cobra is the de-facto standard for Go CLIs. It perfectly matches Vunnel's subcommand structure and provides all needed features (flags, completion, help). Used by virtually every major Go CLI tool.

**Example Structure:**
```go
// cmd/root.go
var rootCmd = &cobra.Command{
    Use:   "vulnz-go",
    Short: "Vulnerability data aggregation tool",
}

// cmd/run.go
var runCmd = &cobra.Command{
    Use:   "run [provider]",
    Short: "Run vulnerability data provider",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        // Implementation
    },
}

func init() {
    rootCmd.AddCommand(runCmd)
    runCmd.Flags().StringP("output", "o", "./data", "Output directory")
}
```

---

#### Option B: github.com/urfave/cli/v3

**GitHub:** https://github.com/urfave/cli  
**Import:** `github.com/urfave/cli/v3`  
**License:** MIT  
**Stars:** 24,000 | **Forks:** 1,800 | **Last Release:** v3.8.0 (Mar 2026)

**Pros:**
- Declarative API (simpler than Cobra)
- Fast
- Good documentation at cli.urfave.org
- Shell completion support
- YAML/TOML/JSON config support

**Cons:**
- Less feature-rich than Cobra
- Smaller ecosystem
- No command generation tools
- Less common in enterprise projects

**Recommendation:** ⚠️ **Consider for simpler CLIs**

**Rationale:** Good alternative if Cobra feels too heavy, but Cobra's ecosystem and tooling make it better for a project like vulnz-go.

---

## 6. Testing Framework

**Purpose:** Port 79 Python pytest tests to Go, including snapshot testing.

### Evaluation

#### Option A: github.com/stretchr/testify + stdlib ✅ RECOMMENDED

**GitHub:** https://github.com/stretchr/testify  
**Import:** `github.com/stretchr/testify`  
**License:** MIT  
**Stars:** 25,900 | **Forks:** 1,700 | **Last Release:** v1.11.1 (Aug 2025)

**Pros:**
- **Industry standard** (642k imports!)
- Clean assertion API (`assert.Equal`, `assert.NoError`)
- Mock support (`mock.Mock`)
- Suite support (`suite.Suite`) for setup/teardown
- Require package (fails test immediately)
- Compatible with stdlib `testing`
- Excellent documentation
- Active maintenance

**Cons:**
- No built-in snapshot testing (use separate library)
- Suite package doesn't support parallel tests

**Maintenance Status:** 🟢 VERY ACTIVE  
- Last release: Aug 2025
- Huge community
- Maintained at v1 (stable API)

**Recommendation:** ✅ **Use testify + stdlib**

**Rationale:** Testify is the standard testing toolkit in Go. It provides pytest-like assertions while maintaining Go idioms. For snapshot testing, use `github.com/bradleyjkemp/cupaloy`.

**Example:**
```go
import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"
)

// Table-driven tests (like pytest.mark.parametrize)
func TestOVALParser(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    OVALDefinitions
        wantErr bool
    }{
        {"valid OVAL", "testdata/valid.xml", expectedDef, false},
        {"invalid XML", "testdata/invalid.xml", nil, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseOVAL(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}

// Suite-based tests (like pytest fixtures)
type ProviderTestSuite struct {
    suite.Suite
    tmpDir string
}

func (s *ProviderTestSuite) SetupTest() {
    s.tmpDir = t.TempDir()
}

func (s *ProviderTestSuite) TestRunProvider() {
    // Test implementation
    assert.NotEmpty(s.T(), s.tmpDir)
}

func TestProviderSuite(t *testing.T) {
    suite.Run(t, new(ProviderTestSuite))
}
```

---

#### Snapshot Testing: github.com/bradleyjkemp/cupaloy

**GitHub:** https://github.com/bradleyjkemp/cupaloy  
**Import:** `github.com/bradleyjkemp/cupaloy/v2`  
**License:** MIT  
**Stars:** 310

**Pros:**
- Snapshot testing like Jest/pytest-snapshot
- Automatic snapshot creation/update
- Works with testify
- Simple API

**Example:**
```go
func TestOVALSnapshot(t *testing.T) {
    result := ParseOVAL("testdata/rhel.xml")
    cupaloy.SnapshotT(t, result)
}
```

**Recommendation:** ✅ **Use for snapshot testing**

---

#### Option B: Stdlib testing only

**Pros:**
- No dependencies
- Fast
- Idiomatic Go

**Cons:**
- Verbose assertions
- Manual setup/teardown
- No mocking
- No snapshot testing

**Recommendation:** ⚠️ **Insufficient for complex tests**

---

## Summary Table

| Category | Library | Version | Stars | Status | Recommendation |
|----------|---------|---------|-------|--------|----------------|
| **OVAL Parser** | github.com/quay/goval-parser | v0.8.8 | 7 | 🟢 Active | ✅ **Use** |
| **CSAF Parser** | github.com/gocsaf/csaf/v3 | v3.5.1 | 60 | 🟢 Very Active | ✅ **Use** |
| **GraphQL Client** | github.com/hasura/go-graphql-client | v0.15.1 | 470 | 🟢 Very Active | ✅ **Use** |
| **JSON Schema** | github.com/santhosh-tekuri/jsonschema/v6 | v6.0.2 | 1.2k | 🟢 Very Active | ✅ **Use** |
| **CLI Framework** | github.com/spf13/cobra | v1.10.2 | 43.5k | 🟢 Very Active | ✅ **Use** |
| **Testing** | github.com/stretchr/testify | v1.11.1 | 25.9k | 🟢 Very Active | ✅ **Use** |
| **Snapshot Testing** | github.com/bradleyjkemp/cupaloy/v2 | v2.x | 310 | 🟢 Active | ✅ **Use** |

---

## Next Steps

1. **Initialize go.mod** with recommended libraries:
```bash
go get github.com/quay/goval-parser@v0.8.8
go get github.com/gocsaf/csaf/v3@v3.5.1
go get github.com/hasura/go-graphql-client@v0.15.1
go get github.com/santhosh-tekuri/jsonschema/v6@v6.0.2
go get github.com/spf13/cobra@v1.10.2
go get github.com/stretchr/testify@v1.11.1
go get github.com/bradleyjkemp/cupaloy/v2@latest
```

2. **Create CLI structure** using Cobra generator:
```bash
cobra-cli init
cobra-cli add run
cobra-cli add list
cobra-cli add clear
cobra-cli add status
cobra-cli add config
```

3. **Set up testing infrastructure:**
   - Create `internal/testutil` package with common fixtures
   - Add `testdata/` directories for test inputs
   - Configure `cupaloy` for snapshot tests
   - Set up `suite.Suite` for provider integration tests

4. **Implement providers:**
   - Start with OVAL providers (Red Hat, Ubuntu) using goval-parser
   - Add CSAF providers (Red Hat CSAF, SUSE CSAF) using gocsaf
   - Implement GitHub Security Advisories using hasura/go-graphql-client

5. **Validation layer:**
   - Use santhosh-tekuri/jsonschema to validate output against OSV schema
   - Create custom validators for provider-specific requirements

---

## References

- OVAL Specification: https://oval.mitre.org/
- CSAF Specification: https://docs.oasis-open.org/csaf/csaf/v2.0/
- GitHub GraphQL API: https://docs.github.com/en/graphql
- JSON Schema: https://json-schema.org/
- OSV Schema: https://ossf.github.io/osv-schema/

---

**Document Version:** 1.0  
**Last Updated:** March 30, 2026  
**Engram Task ID:** 6980df19-e85f-4112-8045-02c0618954de
