package euvd_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestEUVD(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "EUVD Provider Suite")
}
