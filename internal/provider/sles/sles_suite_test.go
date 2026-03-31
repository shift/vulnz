package sles_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSLES(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SLES Provider Suite")
}
