package wolfi_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestWolfi(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Wolfi Provider Suite")
}
