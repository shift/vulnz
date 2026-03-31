package chainguard_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestChainguard(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chainguard Provider Suite")
}
