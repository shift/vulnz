package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/shift/vulnz/internal/grc"
	"github.com/spf13/cobra"
)

var (
	grcFramework string
)

var grcCmd = &cobra.Command{
	Use:   "grc",
	Short: "Manage GRC framework controls",
	Long: `Interact with Governance, Risk, and Compliance (GRC) framework providers.

List available frameworks or output their controls as JSON.

Examples:
  # List all available GRC frameworks
  vulnz grc list

  # Output controls for a specific framework as JSON
  vulnz grc run --framework cis_benchmarks

  # List frameworks with JSON output
  vulnz grc list --output json`,
}

var grcListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available GRC frameworks",
	Long:  `List all registered GRC framework providers by name.`,
	RunE:  runGrcList,
}

var grcRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Output framework controls as JSON",
	Long: `Run a GRC framework provider and output its controls as JSON.

The provider will use its embedded control set. If the provider supports
remote fetching and the download fails, it will fall back to embedded controls.`,
	RunE: runGrcRun,
}

func init() {
	rootCmd.AddCommand(grcCmd)
	grcCmd.AddCommand(grcListCmd)
	grcCmd.AddCommand(grcRunCmd)

	grcRunCmd.Flags().StringVarP(&grcFramework, "framework", "f", "", "GRC framework name (required)")
	grcRunCmd.MarkFlagRequired("framework")
}

func runGrcList(cmd *cobra.Command, args []string) error {
	frameworks := grc.ListFrameworks()

	if outputFmt == "json" {
		return printGrcListJSON(frameworks)
	}

	printGrcListTable(frameworks)
	return nil
}

func printGrcListTable(frameworks []string) {
	if len(frameworks) == 0 {
		printWarning("No GRC frameworks found")
		return
	}

	fmt.Println()
	fmt.Println(colorize(color.New(color.FgWhite, color.Bold), "Available GRC Frameworks"))
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("%-4s  %s\n",
		colorize(color.New(color.FgCyan, color.Bold), "#"),
		colorize(color.New(color.FgCyan, color.Bold), "FRAMEWORK"),
	)
	fmt.Println(strings.Repeat("─", 40))

	for i, name := range frameworks {
		fmt.Printf("%-4d  %s\n", i+1, colorize(color.New(color.FgWhite), name))
	}

	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("\nTotal: %s frameworks\n\n", colorize(color.New(color.FgCyan, color.Bold), fmt.Sprintf("%d", len(frameworks))))
	printInfo("Run a framework with: vulnz grc run --framework <name>")
}

func printGrcListJSON(frameworks []string) error {
	output := map[string]interface{}{
		"frameworks": frameworks,
		"count":      len(frameworks),
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func runGrcRun(cmd *cobra.Command, args []string) error {
	if grcFramework == "" {
		return fmt.Errorf("--framework is required")
	}

	frameworks := grc.ListFrameworks()
	valid := false
	for _, f := range frameworks {
		if f == grcFramework {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("unknown framework %q\nAvailable: %s", grcFramework, strings.Join(frameworks, ", "))
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	controls, err := grc.GetFrameworkControls(grcFramework, logger)
	if err != nil {
		return fmt.Errorf("run framework %s: %w", grcFramework, err)
	}

	if len(controls) == 0 {
		printWarning("No controls found for framework %q", grcFramework)
		return nil
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(controls)
}
