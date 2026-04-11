package pbt

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shift/vulnz/internal/utils/csaf"
	"github.com/shift/vulnz/internal/utils/oval"
	"github.com/shift/vulnz/internal/utils/rpm"
	"github.com/shift/vulnz/internal/utils/vulnerability"
)

func FuzzParseVulnerability(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var vuln vulnerability.Vulnerability
		_ = json.Unmarshal(data, &vuln)

		_ = vuln.Name
		_ = vuln.NamespaceName
		_ = vuln.Severity
		_ = vuln.Link
	})
}

func FuzzParseCSAF(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		parser := csaf.NewParser()
		ctx := context.Background()
		_ = parser.ParseBytes(ctx, data)
	})
}

func FuzzParseOVAL(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		parser := oval.NewParser()
		ctx := context.Background()
		_ = parser.ParseBytes(ctx, data)
	})
}

func FuzzRPMCompare(f *testing.F) {
	f.Fuzz(func(t *testing.T, v1, v2 []byte) {
		ver1, err1 := rpm.Parse(string(v1))
		ver2, err2 := rpm.Parse(string(v2))
		if err1 != nil || err2 != nil {
			return
		}
		_ = ver1.Compare(ver2)
	})
}

func FuzzVulnerabilityToPayload(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var vuln vulnerability.Vulnerability
		if err := json.Unmarshal(data, &vuln); err != nil {
			return
		}

		_ = vuln.ToPayload()
	})
}
