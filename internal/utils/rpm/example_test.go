package rpm_test

import (
	"fmt"
	"log"

	"github.com/shift/vulnz/internal/utils/rpm"
)

// Example 1: Basic version comparison
func basicComparison() {
	fmt.Println("=== Example 1: Basic Version Comparison ===")

	v1, err := rpm.Parse("1.2.3")
	if err != nil {
		log.Fatal(err)
	}

	v2, err := rpm.Parse("1.2.4")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s < %s: %v\n", v1, v2, v1.Less(v2))
	fmt.Printf("%s == %s: %v\n", v1, v2, v1.Equal(v2))
	fmt.Printf("%s > %s: %v\n", v1, v2, v1.Greater(v2))
	fmt.Println()
}

// Example 2: Epoch comparison
func epochComparison() {
	fmt.Println("=== Example 2: Epoch Comparison ===")

	v1 := rpm.MustParse("2:1.0-1")
	v2 := rpm.MustParse("1:9999-999")

	fmt.Printf("%s vs %s\n", v1, v2)
	fmt.Printf("Result: %s is newer (epoch %d > epoch %d)\n\n",
		v1, v1.Epoch, v2.Epoch)
}

// Example 3: Real-world OpenSSL vulnerability check
func opensslVulnerabilityCheck() {
	fmt.Println("=== Example 3: OpenSSL Vulnerability Check ===")

	installed := rpm.MustParse("2:1.1.1k-7.el8_6")
	fixed := rpm.MustParse("2:1.1.1k-8.el8_6")

	fmt.Printf("Installed: %s\n", installed)
	fmt.Printf("Fixed in:  %s\n", fixed)

	if installed.Less(fixed) {
		fmt.Println("Status: VULNERABLE - Please upgrade!")
	} else {
		fmt.Println("Status: PATCHED")
	}
	fmt.Println()
}

// Example 4: Kernel version comparison
func kernelVersionComparison() {
	fmt.Println("=== Example 4: Kernel Version Comparison ===")

	kernels := []string{
		"4.18.0-372.el8",
		"4.18.0-373.el8",
		"4.18.0-372.32.1.el8_6",
		"5.14.0-284.el9",
	}

	fmt.Println("Kernel versions (oldest to newest):")
	versions := make([]*rpm.Version, len(kernels))
	for i, k := range kernels {
		versions[i] = rpm.MustParse(k)
	}

	// Simple bubble sort for demonstration
	for i := 0; i < len(versions); i++ {
		for j := i + 1; j < len(versions); j++ {
			if versions[i].Greater(versions[j]) {
				versions[i], versions[j] = versions[j], versions[i]
			}
		}
	}

	for _, v := range versions {
		fmt.Printf("  %s\n", v)
	}
	fmt.Println()
}

// Example 5: Pre-release version handling
func preReleaseVersions() {
	fmt.Println("=== Example 5: Pre-release Versions (Tilde) ===")

	versions := []string{
		"1.0~alpha",
		"1.0~beta",
		"1.0~rc1",
		"1.0~rc2",
		"1.0",
		"1.0-1",
	}

	fmt.Println("Version progression:")
	for i, v := range versions {
		ver := rpm.MustParse(v)
		fmt.Printf("%d. %s", i+1, ver)
		if i > 0 {
			prev := rpm.MustParse(versions[i-1])
			if ver.Greater(prev) {
				fmt.Printf(" (newer)")
			}
		}
		fmt.Println()
	}
	fmt.Println()
}

// Example 6: Distribution tag comparison
func distTagComparison() {
	fmt.Println("=== Example 6: Distribution Tags ===")

	examples := []struct {
		v1, v2 string
		desc   string
	}{
		{"1.0-1.el7", "1.0-1.el8", "RHEL 7 vs RHEL 8"},
		{"1.0-1.el8", "1.0-1.el9", "RHEL 8 vs RHEL 9"},
		{"1.0-1.el8_6", "1.0-1.el8_7", "RHEL 8.6 vs RHEL 8.7"},
		{"1.0-1.fc38", "1.0-1.fc39", "Fedora 38 vs Fedora 39"},
	}

	for _, ex := range examples {
		v1 := rpm.MustParse(ex.v1)
		v2 := rpm.MustParse(ex.v2)
		fmt.Printf("%s: %s < %s = %v\n", ex.desc, v1, v2, v1.Less(v2))
	}
	fmt.Println()
}

// Example 7: Version validation
func versionValidation() {
	fmt.Println("=== Example 7: Version Validation ===")

	testCases := []string{
		"1.2.3",
		"2:1.2.3-4.el8",
		"invalid:version",
		"",
		"-1:1.0",
	}

	for _, tc := range testCases {
		if tc == "" {
			fmt.Printf("Testing: (empty string)\n")
		} else {
			fmt.Printf("Testing: %s\n", tc)
		}

		if err := rpm.Validate(tc); err != nil {
			fmt.Printf("  Invalid: %v\n", err)
		} else {
			fmt.Printf("  Valid\n")
		}
	}
	fmt.Println()
}

// Example 8: Vulnerability matching in a provider
func vulnerabilityMatching() {
	fmt.Println("=== Example 8: Vulnerability Matching ===")

	type Package struct {
		Name    string
		Version string
	}

	type Vulnerability struct {
		CVE          string
		Package      string
		FixedVersion string
	}

	// Simulated installed packages
	installed := []Package{
		{"openssl", "2:1.1.1k-7.el8_6"},
		{"kernel", "4.18.0-372.el8"},
		{"glibc", "2.28-164.el8"},
	}

	// Simulated vulnerabilities
	vulnerabilities := []Vulnerability{
		{"CVE-2023-0286", "openssl", "2:1.1.1k-8.el8_6"},
		{"CVE-2023-1234", "kernel", "4.18.0-373.el8"},
		{"CVE-2023-5678", "glibc", "2.28-165.el8"},
	}

	fmt.Println("Scanning for vulnerabilities...")
	for _, pkg := range installed {
		installedVer := rpm.MustParse(pkg.Version)

		for _, vuln := range vulnerabilities {
			if vuln.Package != pkg.Name {
				continue
			}

			fixedVer := rpm.MustParse(vuln.FixedVersion)

			if installedVer.Less(fixedVer) {
				fmt.Printf("  [!] %s %s is affected by %s (fix: %s)\n",
					pkg.Name, installedVer, vuln.CVE, fixedVer)
			}
		}
	}
	fmt.Println()
}

// Example 9: Creating versions programmatically
func createVersions() {
	fmt.Println("=== Example 9: Creating Versions ===")

	// From components
	v1, err := rpm.New(2, "1.2.3", "4.el8")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created: %s\n", v1)

	// MustNew (panics on error)
	v2 := rpm.MustNew(1, "3.0.0", "1.fc39")
	fmt.Printf("Created: %s\n", v2)

	// From string
	v3 := rpm.MustParse("2:1.1.1k-7.el8_6")
	fmt.Printf("Parsed:  %s\n", v3)
	fmt.Printf("  Epoch:   %d\n", v3.Epoch)
	fmt.Printf("  Version: %s\n", v3.Version)
	fmt.Printf("  Release: %s\n", v3.Release)
	fmt.Println()
}

// Example 10: Numeric vs alpha comparison
func numericVsAlpha() {
	fmt.Println("=== Example 10: Numeric vs Alpha ===")

	examples := []struct {
		v1, v2 string
	}{
		{"1.10", "1.9"},     // Numeric: 10 > 9
		{"1.0.1", "1.0.a"},  // Numeric beats alpha
		{"1.2a", "1.2b"},    // Alpha comparison
		{"1.0.0", "1.0"},    // Trailing zeros
		{"1.2.3a", "1.2.3"}, // Extra segment
	}

	for _, ex := range examples {
		v1 := rpm.MustParse(ex.v1)
		v2 := rpm.MustParse(ex.v2)
		cmp := v1.Compare(v2)
		symbol := "=="
		if cmp < 0 {
			symbol = "<"
		} else if cmp > 0 {
			symbol = ">"
		}
		fmt.Printf("%s %s %s\n", v1, symbol, v2)
	}
	fmt.Println()
}

func main() {
	fmt.Println("RPM Version Comparison Examples")
	fmt.Println("================================")
	fmt.Println()

	basicComparison()
	epochComparison()
	opensslVulnerabilityCheck()
	kernelVersionComparison()
	preReleaseVersions()
	distTagComparison()
	versionValidation()
	vulnerabilityMatching()
	createVersions()
	numericVsAlpha()

	fmt.Println("All examples completed successfully!")
}
