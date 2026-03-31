package certfr_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCERTFR(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CERT-FR Provider Suite")
}
