package ubuntu_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestUbuntu(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ubuntu Provider Suite")
}
