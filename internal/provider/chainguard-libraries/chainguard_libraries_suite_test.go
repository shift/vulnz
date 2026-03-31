package chainguardlibraries_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestChainguardLibraries(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chainguard Libraries Provider Suite")
}
