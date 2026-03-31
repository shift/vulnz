package minimos_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMinimos(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Minimos Provider Suite")
}
