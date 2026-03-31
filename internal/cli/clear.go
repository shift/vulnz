package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shift/vulnz/internal/provider"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	clearProviders []string
	clearAll       bool
	clearWorkspace string
	clearForce     bool
)

// clearCmd represents the clear command
var clearCmd = &cobra.Command{
	Use:   "clear [provider]",
	Short: "Clear provider workspace",
	Long: `Clear workspace data for one or more providers. This removes all downloaded
data, parsed results, and metadata for the specified providers.

Warning: This operation cannot be undone!

Examples:
  # Clear a single provider
  vulnz clear alpine

  # Clear multiple providers
  vulnz clear --provider alpine,debian,ubuntu

  # Clear all providers (with confirmation)
  vulnz clear --all

  # Clear without confirmation prompt
  vulnz clear --all --force`,
	RunE: runClear,
}

func init() {
	rootCmd.AddCommand(clearCmd)

	clearCmd.Flags().StringSliceVarP(&clearProviders, "provider", "p", []string{}, "specific provider(s) to clear (comma-separated)")
	clearCmd.Flags().BoolVarP(&clearAll, "all", "a", false, "clear all providers")
	clearCmd.Flags().StringVarP(&clearWorkspace, "workspace", "w", "./data", "workspace directory")
	clearCmd.Flags().BoolVarP(&clearForce, "force", "f", false, "skip confirmation prompt")
}

func runClear(cmd *cobra.Command, args []string) error {
	logger := getLogger()

	// Determine which providers to clear
	var providers []string

	// Provider from positional argument
	if len(args) > 0 {
		providers = append(providers, args[0])
	}

	// Providers from --provider flag
	if len(clearProviders) > 0 {
		providers = append(providers, clearProviders...)
	}

	// All providers if --all flag
	if clearAll {
		providers = provider.List()
		if len(providers) == 0 {
			printError("No providers found in workspace")
			return fmt.Errorf("no providers to clear")
		}
	}

	if len(providers) == 0 {
		printError("No providers specified. Use --provider, --all, or provide provider as argument.")
		return fmt.Errorf("no providers specified")
	}

	// Remove duplicates
	providers = uniqueStrings(providers)

	// Filter to only existing providers in workspace
	existingProviders := filterExistingProviders(providers, clearWorkspace)
	if len(existingProviders) == 0 {
		printWarning("No provider workspaces found for: %s", strings.Join(providers, ", "))
		return nil
	}

	// Show what will be cleared
	fmt.Println()
	if clearAll {
		printWarning("This will clear ALL provider workspaces:")
	} else {
		printWarning("This will clear the following provider workspaces:")
	}
	for _, p := range existingProviders {
		size := getDirectorySize(filepath.Join(clearWorkspace, p))
		fmt.Printf("  • %s (%s)\n", colorize(color.New(color.FgCyan), p), formatBytes(size))
	}
	fmt.Printf("\nWorkspace: %s\n", clearWorkspace)
	fmt.Println()

	// Confirm unless --force
	if !clearForce {
		confirmed := confirmAction("Are you sure you want to clear these workspaces? This cannot be undone.")
		if !confirmed {
			printInfo("Operation cancelled")
			return nil
		}
	}

	// Clear each provider workspace
	successCount := 0
	failCount := 0

	for _, providerName := range existingProviders {
		workspacePath := filepath.Join(clearWorkspace, providerName)

		logger.Infof("Clearing workspace: %s", workspacePath)

		if err := os.RemoveAll(workspacePath); err != nil {
			printError("Failed to clear %s: %v", providerName, err)
			failCount++
		} else {
			printSuccess("Cleared %s", providerName)
			successCount++
		}
	}

	// Print summary
	fmt.Println()
	fmt.Println(strings.Repeat("─", 60))
	if failCount == 0 {
		printSuccess("Successfully cleared %d provider workspace(s)", successCount)
	} else {
		printWarning("Cleared %d workspace(s), %d failed", successCount, failCount)
	}

	return nil
}

// filterExistingProviders returns only providers that have workspaces
func filterExistingProviders(providers []string, workspace string) []string {
	existing := []string{}

	for _, p := range providers {
		path := filepath.Join(workspace, p)
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			existing = append(existing, p)
		}
	}

	return existing
}

// getDirectorySize returns the total size of a directory in bytes
func getDirectorySize(path string) int64 {
	var size int64

	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})

	if err != nil {
		return 0
	}

	return size
}

// formatBytes returns a human-readable byte size
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// confirmAction prompts the user for confirmation
func confirmAction(message string) bool {
	fmt.Printf("%s [y/N]: ", colorize(color.New(color.FgYellow), message))

	var response string
	fmt.Scanln(&response)

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
