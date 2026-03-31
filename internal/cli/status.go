package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	statusWorkspace string
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status [provider]",
	Short: "Show provider status",
	Long: `Show status information for one or more providers, including:
  - Last run timestamp
  - Number of vulnerabilities
  - Data freshness
  - Workspace size

Examples:
  # Show status for a single provider
  vulnz status alpine

  # Show status for all providers
  vulnz status

  # Show status with JSON output
  vulnz status --output json`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)

	statusCmd.Flags().StringVarP(&statusWorkspace, "workspace", "w", "./data", "workspace directory")
}

func runStatus(cmd *cobra.Command, args []string) error {
	var providers []string

	// If provider specified as argument, show only that one
	if len(args) > 0 {
		providers = []string{args[0]}
	} else {
		// Show all providers that have workspaces
		providers = findWorkspaceProviders(statusWorkspace)
	}

	if len(providers) == 0 {
		printWarning("No provider workspaces found in %s", statusWorkspace)
		printInfo("Run a provider first with: vulnz run <provider>")
		return nil
	}

	// Get status for each provider
	statuses := make([]ProviderStatusInfo, 0, len(providers))
	for _, providerName := range providers {
		status := getProviderStatusInfo(providerName, statusWorkspace)
		if status != nil {
			statuses = append(statuses, *status)
		}
	}

	// Sort by name
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Provider < statuses[j].Provider
	})

	// Output as JSON if requested
	if outputFmt == "json" {
		return printStatusJSON(statuses)
	}

	// Print text table
	if len(args) > 0 && len(statuses) == 1 {
		// Detailed view for single provider
		printDetailedStatus(statuses[0])
	} else {
		// Table view for multiple providers
		printStatusTable(statuses)
	}

	return nil
}

// ProviderStatusInfo represents detailed status information
type ProviderStatusInfo struct {
	Provider      string    `json:"provider"`
	LastRun       time.Time `json:"last_run"`
	VulnCount     int       `json:"vulnerability_count"`
	WorkspaceSize int64     `json:"workspace_size_bytes"`
	DataAge       string    `json:"data_age"`
	Freshness     string    `json:"freshness"`
	URLs          []string  `json:"urls,omitempty"`
	Store         string    `json:"store,omitempty"`
	Version       int       `json:"version,omitempty"`
}

// findWorkspaceProviders finds all provider directories in workspace
func findWorkspaceProviders(workspace string) []string {
	providers := []string{}

	entries, err := os.ReadDir(workspace)
	if err != nil {
		return providers
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Check if it has a metadata.json file (valid provider workspace)
			metadataPath := filepath.Join(workspace, entry.Name(), "metadata.json")
			if _, err := os.Stat(metadataPath); err == nil {
				providers = append(providers, entry.Name())
			} else {
				// Even without metadata, if it has results or input dirs, include it
				resultsPath := filepath.Join(workspace, entry.Name(), "results")
				inputPath := filepath.Join(workspace, entry.Name(), "input")
				if dirExists(resultsPath) || dirExists(inputPath) {
					providers = append(providers, entry.Name())
				}
			}
		}
	}

	return providers
}

// dirExists checks if a directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// getProviderStatusInfo retrieves status information for a provider
func getProviderStatusInfo(provider, workspace string) *ProviderStatusInfo {
	workspacePath := filepath.Join(workspace, provider)

	status := &ProviderStatusInfo{
		Provider: provider,
	}

	// Get workspace size
	status.WorkspaceSize = getDirectorySize(workspacePath)

	// Try to load metadata
	metadataPath := filepath.Join(workspacePath, "metadata.json")
	metadata := loadMetadata(metadataPath)

	if metadata != nil {
		status.LastRun = metadata.Timestamp
		status.URLs = metadata.URLs
		status.Store = metadata.Store
		status.Version = metadata.Version

		// Calculate data age and freshness
		status.DataAge = formatDuration(time.Since(metadata.Timestamp))
		status.Freshness = calculateFreshness(metadata.Timestamp)
	}

	// Count vulnerabilities (estimate from results directory)
	resultsPath := filepath.Join(workspacePath, "results")
	status.VulnCount = estimateVulnerabilityCount(resultsPath)

	return status
}

// MetadataFile represents the structure of metadata.json
type MetadataFile struct {
	Provider            string    `json:"provider"`
	Version             int       `json:"version"`
	DistributionVersion int       `json:"distribution_version"`
	Timestamp           time.Time `json:"timestamp"`
	URLs                []string  `json:"urls"`
	Store               string    `json:"store"`
	Stale               bool      `json:"stale"`
}

// loadMetadata loads metadata from a file
func loadMetadata(path string) *MetadataFile {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var metadata MetadataFile
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil
	}

	return &metadata
}

// estimateVulnerabilityCount estimates the number of vulnerabilities
func estimateVulnerabilityCount(resultsPath string) int {
	count := 0

	filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			count++
		}
		return nil
	})

	return count
}

// calculateFreshness returns a freshness indicator
func calculateFreshness(lastRun time.Time) string {
	age := time.Since(lastRun)

	if age < 24*time.Hour {
		return "fresh"
	} else if age < 7*24*time.Hour {
		return "recent"
	} else if age < 30*24*time.Hour {
		return "stale"
	} else {
		return "very stale"
	}
}

// formatDuration returns a human-readable duration
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	} else {
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
}

// printStatusTable prints provider statuses in a table
func printStatusTable(statuses []ProviderStatusInfo) {
	if len(statuses) == 0 {
		printWarning("No provider status information available")
		return
	}

	// Print header
	fmt.Println()
	fmt.Println(colorize(color.New(color.FgWhite, color.Bold), "Provider Status"))
	fmt.Println(strings.Repeat("─", 90))
	fmt.Printf("%-15s %-12s %-15s %-12s %s\n",
		colorize(color.New(color.FgCyan, color.Bold), "PROVIDER"),
		colorize(color.New(color.FgCyan, color.Bold), "VULNS"),
		colorize(color.New(color.FgCyan, color.Bold), "LAST RUN"),
		colorize(color.New(color.FgCyan, color.Bold), "FRESHNESS"),
		colorize(color.New(color.FgCyan, color.Bold), "SIZE"),
	)
	fmt.Println(strings.Repeat("─", 90))

	// Print statuses
	for _, s := range statuses {
		lastRun := "never"
		if !s.LastRun.IsZero() {
			lastRun = formatTimeAgo(s.LastRun)
		}

		// Color code freshness
		freshnessColor := color.New(color.FgGreen)
		switch s.Freshness {
		case "recent":
			freshnessColor = color.New(color.FgYellow)
		case "stale":
			freshnessColor = color.New(color.FgRed)
		case "very stale":
			freshnessColor = color.New(color.FgRed, color.Bold)
		}

		fmt.Printf("%-15s %-12s %-15s %-12s %s\n",
			s.Provider,
			formatNumber(s.VulnCount),
			lastRun,
			colorize(freshnessColor, s.Freshness),
			formatBytes(s.WorkspaceSize),
		)
	}

	fmt.Println(strings.Repeat("─", 90))
	fmt.Printf("\nTotal: %d provider(s)\n\n", len(statuses))
}

// printDetailedStatus prints detailed status for a single provider
func printDetailedStatus(status ProviderStatusInfo) {
	fmt.Println()
	fmt.Println(colorize(color.New(color.FgWhite, color.Bold), fmt.Sprintf("Provider: %s", status.Provider)))
	fmt.Println(strings.Repeat("─", 60))

	if status.LastRun.IsZero() {
		printWarning("No run data available for this provider")
		fmt.Printf("\nWorkspace size: %s\n\n", formatBytes(status.WorkspaceSize))
		return
	}

	// Basic info
	fmt.Printf("Last run:         %s (%s)\n", status.LastRun.Format("2006-01-02 15:04:05"), formatTimeAgo(status.LastRun))
	fmt.Printf("Data age:         %s\n", status.DataAge)

	// Color code freshness
	freshnessColor := color.New(color.FgGreen)
	switch status.Freshness {
	case "recent":
		freshnessColor = color.New(color.FgYellow)
	case "stale":
		freshnessColor = color.New(color.FgRed)
	case "very stale":
		freshnessColor = color.New(color.FgRed, color.Bold)
	}
	fmt.Printf("Freshness:        %s\n", colorize(freshnessColor, status.Freshness))

	fmt.Printf("Vulnerabilities:  %s\n", colorize(color.New(color.FgCyan, color.Bold), formatNumber(status.VulnCount)))
	fmt.Printf("Workspace size:   %s\n", formatBytes(status.WorkspaceSize))

	if status.Store != "" {
		fmt.Printf("Storage backend:  %s\n", status.Store)
	}

	if status.Version > 0 {
		fmt.Printf("Version:          %d\n", status.Version)
	}

	if len(status.URLs) > 0 {
		fmt.Printf("\nData sources:     %d URL(s)\n", len(status.URLs))
		for i, url := range status.URLs {
			if i < 5 {
				fmt.Printf("  • %s\n", url)
			} else if i == 5 {
				fmt.Printf("  • ... and %d more\n", len(status.URLs)-5)
				break
			}
		}
	}

	fmt.Println()
}

// printStatusJSON outputs status as JSON
func printStatusJSON(statuses []ProviderStatusInfo) error {
	output := map[string]interface{}{
		"providers": statuses,
		"count":     len(statuses),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// formatNumber formats a number with thousands separators
func formatNumber(n int) string {
	if n == 0 {
		return "0"
	}

	str := fmt.Sprintf("%d", n)
	result := ""
	for i, c := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(c)
	}
	return result
}
