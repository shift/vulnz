package certfr_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/shift/vulnz/internal/provider"
)

var _ = Describe("CERT-FR Provider", func() {
	It("should register with the correct name", func() {
		factory, ok := provider.Get("cert-fr")
		Expect(ok).To(BeTrue())
		Expect(factory).NotTo(BeNil())
	})

	It("should create a provider with valid config", func() {
		factory, ok := provider.Get("cert-fr")
		Expect(ok).To(BeTrue())

		config := provider.Config{
			Name: "cert-fr",
			HTTP: provider.HTTPConfig{
				Timeout: 30,
			},
		}

		p, err := factory(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(p).NotTo(BeNil())
		Expect(p.Name()).To(Equal("cert-fr"))
	})

	It("should return correct tags", func() {
		factory, ok := provider.Get("cert-fr")
		Expect(ok).To(BeTrue())

		config := provider.Config{Name: "cert-fr"}
		p, err := factory(config)
		Expect(err).NotTo(HaveOccurred())

		tp, ok := p.(interface{ Tags() []string })
		Expect(ok).To(BeTrue())
		tags := tp.Tags()
		Expect(tags).To(ContainElements("vulnerability", "cert-fr", "anssi"))
	})
})
