package mariner_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMariner(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Mariner Provider Suite")
}
