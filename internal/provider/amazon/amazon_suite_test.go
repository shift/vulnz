package amazon_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAmazon(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Amazon Provider Suite")
}
