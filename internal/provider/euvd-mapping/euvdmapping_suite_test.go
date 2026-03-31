package euvdmapping_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEuvdMapping(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "EUVD Mapping Provider Suite")
}
