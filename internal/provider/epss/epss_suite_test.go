package epss_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEPSS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "EPSS Provider Suite")
}
