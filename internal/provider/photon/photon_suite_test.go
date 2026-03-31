package photon_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPhoton(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Photon Provider Suite")
}
