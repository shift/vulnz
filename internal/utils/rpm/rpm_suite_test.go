package rpm_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRPM(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "RPM Version Comparison Suite")
}
