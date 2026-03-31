package alpine_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAlpine(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Alpine Provider Suite")
}
