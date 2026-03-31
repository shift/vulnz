package eol_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEOL(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "EOL Provider Suite")
}
