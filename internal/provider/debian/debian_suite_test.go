package debian_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestDebian(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Debian Provider Suite")
}
