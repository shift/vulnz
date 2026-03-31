package csatics_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCISAICSCERT(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CISA ICS-CERT Provider Suite")
}
