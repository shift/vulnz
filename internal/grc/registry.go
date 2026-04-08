package grc

import (
	"context"
	"log/slog"
	"sort"
	"sync"

	"github.com/shift/vulnz/pkg/grc"
	"github.com/shift/vulnz/pkg/grc/acn_psnc"
	"github.com/shift/vulnz/pkg/grc/bio"
	"github.com/shift/vulnz/pkg/grc/cis_benchmarks"
	"github.com/shift/vulnz/pkg/grc/cobit"
	"github.com/shift/vulnz/pkg/grc/csa_ccm"
	"github.com/shift/vulnz/pkg/grc/cspm"
	"github.com/shift/vulnz/pkg/grc/disa_stigs"
	"github.com/shift/vulnz/pkg/grc/ens"
	"github.com/shift/vulnz/pkg/grc/fedramp"
	"github.com/shift/vulnz/pkg/grc/hipaa"
	"github.com/shift/vulnz/pkg/grc/iam"
	"github.com/shift/vulnz/pkg/grc/k8s_terraform"
	"github.com/shift/vulnz/pkg/grc/misp"
	"github.com/shift/vulnz/pkg/grc/mitre_attack"
	"github.com/shift/vulnz/pkg/grc/ropa"
	"github.com/shift/vulnz/pkg/grc/scap_xccdf"
	"github.com/shift/vulnz/pkg/grc/secnumcloud"
	"github.com/shift/vulnz/pkg/grc/toms"
	"github.com/shift/vulnz/pkg/grc/veris_vcdb"
	"github.com/shift/vulnz/pkg/storage"
)

type providerFactory func(store storage.Backend, logger *slog.Logger) Runner

type Runner interface {
	Name() string
	Run(ctx context.Context) (int, error)
}

var registry = map[string]providerFactory{
	"acn_psnc":       func(s storage.Backend, l *slog.Logger) Runner { return acn_psnc.New(s, l) },
	"bio":            func(s storage.Backend, l *slog.Logger) Runner { return bio.New(s, l) },
	"cis_benchmarks": func(s storage.Backend, l *slog.Logger) Runner { return cis_benchmarks.New(s, l) },
	"cobit":          func(s storage.Backend, l *slog.Logger) Runner { return cobit.New(s, l) },
	"csa_ccm":        func(s storage.Backend, l *slog.Logger) Runner { return csa_ccm.New(s, l) },
	"cspm":           func(s storage.Backend, l *slog.Logger) Runner { return cspm.New(s, l) },
	"disa_stigs":     func(s storage.Backend, l *slog.Logger) Runner { return disa_stigs.New(s, l) },
	"ens":            func(s storage.Backend, l *slog.Logger) Runner { return ens.New(s, l) },
	"fedramp":        func(s storage.Backend, l *slog.Logger) Runner { return fedramp.New(s, l) },
	"hipaa":          func(s storage.Backend, l *slog.Logger) Runner { return hipaa.New(s, l) },
	"iam":            func(s storage.Backend, l *slog.Logger) Runner { return iam.New(s, l) },
	"k8s_terraform":  func(s storage.Backend, l *slog.Logger) Runner { return k8s_terraform.New(s, l) },
	"misp":           func(s storage.Backend, l *slog.Logger) Runner { return misp.New(s, l) },
	"mitre_attack":   func(s storage.Backend, l *slog.Logger) Runner { return mitre_attack.New(s, l) },
	"ropa":           func(s storage.Backend, l *slog.Logger) Runner { return ropa.New(s, l) },
	"scap_xccdf":     func(s storage.Backend, l *slog.Logger) Runner { return scap_xccdf.New(s, l) },
	"secnumcloud":    func(s storage.Backend, l *slog.Logger) Runner { return secnumcloud.New(s, l) },
	"toms":           func(s storage.Backend, l *slog.Logger) Runner { return toms.New(s, l) },
	"veris_vcdb":     func(s storage.Backend, l *slog.Logger) Runner { return veris_vcdb.New(s, l) },
}

func ListFrameworks() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type CapturingBackend struct {
	mu       sync.Mutex
	Controls []grc.Control
}

func (c *CapturingBackend) WriteControl(_ context.Context, _ string, control interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctrl, ok := control.(grc.Control); ok {
		c.Controls = append(c.Controls, ctrl)
	}
	return nil
}

func (c *CapturingBackend) WriteVulnerability(_ context.Context, _ string, _ interface{}) error {
	return nil
}
func (c *CapturingBackend) WriteMapping(_ context.Context, _, _, _, _ string, _ float64, _ string) error {
	return nil
}
func (c *CapturingBackend) ReadVulnerability(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}
func (c *CapturingBackend) ReadControl(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (c *CapturingBackend) ListMappings(_ context.Context, _ string) ([]storage.MappingRow, error) {
	return nil, nil
}
func (c *CapturingBackend) Close(_ context.Context) error { return nil }

func GetFrameworkControls(name string, logger *slog.Logger) ([]grc.Control, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, nil
	}
	cap := &CapturingBackend{}
	p := factory(cap, logger)
	_, err := p.Run(context.Background())
	return cap.Controls, err
}
