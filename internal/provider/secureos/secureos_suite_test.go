package secureos_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSecureOS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SecureOS Provider Suite")
}
