package bsicertbund_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBSICertBund(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "BSI CERT-Bund Provider Suite")
}
