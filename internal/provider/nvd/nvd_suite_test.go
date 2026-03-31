package nvd_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestNvd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NVD Provider Suite")
}
