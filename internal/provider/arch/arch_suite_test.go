package arch_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestArch(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Arch Provider Suite")
}
