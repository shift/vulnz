package oval_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestOval(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OVAL Utils Suite")
}
