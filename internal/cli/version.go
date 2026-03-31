package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display version, build, and runtime information for vulnz-go.`,
	RunE:  runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) error {
	if outputFmt == "json" {
		return printVersionJSON()
	}

	printVersionText()
	return nil
}

// printVersionText prints version information in text format
func printVersionText() {
	fmt.Println()
	fmt.Println(colorize(color.New(color.FgCyan, color.Bold), "vulnz-go"))
	fmt.Println(colorize(color.New(color.FgWhite), "Vulnerability data aggregator"))
	fmt.Println()

	fmt.Printf("Version:        %s\n", colorize(color.New(color.FgGreen), Version))
	fmt.Printf("Commit:         %s\n", Commit)
	fmt.Printf("Build date:     %s\n", BuildDate)
	fmt.Println()

	fmt.Printf("Go version:     %s\n", runtime.Version())
	fmt.Printf("OS/Arch:        %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()
}

// printVersionJSON outputs version information as JSON
func printVersionJSON() error {
	info := map[string]interface{}{
		"version":    Version,
		"commit":     Commit,
		"build_date": BuildDate,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(info)
}
