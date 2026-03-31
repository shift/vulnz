package bitnami_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBitnami(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Bitnami Provider Suite")
}
