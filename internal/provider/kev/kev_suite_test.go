package kev_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKEV(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "KEV Provider Suite")
}
