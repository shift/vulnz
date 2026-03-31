package csaf_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCSAF(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CSAF Suite")
}
