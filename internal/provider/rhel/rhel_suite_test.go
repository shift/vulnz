package rhel_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRhel(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RHEL Provider Suite")
}
