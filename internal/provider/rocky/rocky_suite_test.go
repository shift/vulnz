package rocky_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRocky(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rocky Linux Provider Suite")
}
