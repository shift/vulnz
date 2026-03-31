package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/shift/vulnz/internal/provider"
	"github.com/spf13/cobra"
)

var (
	runProviders []string
	runAll       bool
	runSince     string
	runWorkspace string
	runParallel  int
)

var runCmd = &cobra.Command{
	Use:   "run [provider]",
	Short: "Run vulnerability data providers",
	Long: `Run one or more vulnerability data providers to fetch and process
vulnerability data. Providers can be specified by name or run all providers.

Examples:
  # Run a single provider
  vulnz run alpine

  # Run multiple providers
  vulnz run --provider alpine,debian,ubuntu

  # Run all providers
  vulnz run --all

  # Run with custom workspace
  vulnz run --provider alpine --workspace /data/vulnz

  # Run providers in parallel (max 8 concurrent)
  vulnz run --all --parallel 8

  # Run only updates since timestamp
  vulnz run --all --since 2024-03-01T00:00:00Z`,
	RunE: runRun,
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringSliceVarP(&runProviders, "provider", "p", []string{}, "specific provider(s) to run (comma-separated)")
	runCmd.Flags().BoolVarP(&runAll, "all", "a", false, "run all providers")
	runCmd.Flags().StringVar(&runSince, "since", "", "only fetch data since timestamp (RFC3339 format)")
	runCmd.Flags().StringVarP(&runWorkspace, "workspace", "w", "./data", "workspace directory")
	runCmd.Flags().IntVar(&runParallel, "parallel", 4, "max parallel providers")
}

func runRun(cmd *cobra.Command, args []string) error {
	var providerNames []string

	if len(args) > 0 {
		providerNames = append(providerNames, args...)
	}

	if len(runProviders) > 0 {
		providerNames = append(providerNames, runProviders...)
	}

	if runAll {
		providerNames = append(providerNames, provider.List()...)
		if len(providerNames) == 0 {
			printError("No providers registered.")
			return fmt.Errorf("no providers available")
		}
	}

	if len(providerNames) == 0 {
		printError("No providers specified. Use --provider, --all, or provide provider as argument.")
		return fmt.Errorf("no providers specified")
	}

	providerNames = uniqueStrings(providerNames)

	var sinceTime *time.Time
	if runSince != "" {
		t, err := time.Parse(time.RFC3339, runSince)
		if err != nil {
			printError("Invalid --since timestamp format. Use RFC3339 (e.g., 2024-03-01T00:00:00Z)")
			return fmt.Errorf("parse --since: %w", err)
		}
		sinceTime = &t
	}

	slogLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	if verbose || outputFmt != "json" {
		printInfo("Starting vulnerability data collection")
		fmt.Printf("  Workspace: %s\n", runWorkspace)
		fmt.Printf("  Providers: %s\n", strings.Join(providerNames, ", "))
		fmt.Printf("  Parallel:  %d\n", runParallel)
		if sinceTime != nil {
			fmt.Printf("  Since:     %s\n", sinceTime.Format(time.RFC3339))
		}
		fmt.Println()
	}

	exec := provider.NewExecutor(provider.ExecutorConfig{
		MaxParallel: runParallel,
		Workspace:   runWorkspace,
	}, slogLogger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startTime := time.Now()
	execResults, err := exec.Run(ctx, providerNames)
	if err != nil {
		return fmt.Errorf("executor run: %w", err)
	}

	results := make([]ProviderResult, 0, len(execResults))
	for _, r := range execResults {
		result := ProviderResult{
			Provider:  r.Provider,
			Count:     r.Count,
			URLs:      r.URLs,
			Duration:  r.Duration,
			Timestamp: startTime,
		}
		if r.Err != nil {
			result.Error = r.Err.Error()
		} else {
			result.Success = true
		}
		results = append(results, result)
	}

	totalDuration := time.Since(startTime)

	if outputFmt == "json" {
		return printJSONResults(results, totalDuration)
	}

	for _, r := range results {
		printProviderResult(r)
		fmt.Println()
	}

	printSummary(results, totalDuration)
	return nil
}

type ProviderResult struct {
	Provider  string        `json:"provider"`
	Success   bool          `json:"success"`
	Count     int           `json:"count"`
	URLs      []string      `json:"urls,omitempty"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

func printProviderResult(result ProviderResult) {
	if result.Success {
		printSuccess("%s completed in %s", result.Provider, result.Duration.Round(time.Millisecond))
		fmt.Printf("  Vulnerabilities: %d\n", result.Count)
		if len(result.URLs) > 0 {
			fmt.Printf("  Sources: %d URLs\n", len(result.URLs))
		}
	} else {
		printError("%s failed after %s", result.Provider, result.Duration.Round(time.Millisecond))
		if result.Error != "" {
			fmt.Printf("  Error: %s\n", result.Error)
		}
	}
}

func printSummary(results []ProviderResult, totalDuration time.Duration) {
	successCount := 0
	failCount := 0
	totalVulns := 0

	for _, r := range results {
		if r.Success {
			successCount++
			totalVulns += r.Count
		} else {
			failCount++
		}
	}

	fmt.Println(strings.Repeat("─", 60))
	fmt.Println(colorize(color.New(color.FgWhite, color.Bold), "Summary"))
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("Total providers:      %d\n", len(results))
	fmt.Printf("Successful:           %s\n", colorize(color.New(color.FgGreen), fmt.Sprintf("%d", successCount)))
	fmt.Printf("Failed:               %s\n", colorize(color.New(color.FgRed), fmt.Sprintf("%d", failCount)))
	fmt.Printf("Total vulnerabilities: %s\n", colorize(color.New(color.FgCyan, color.Bold), fmt.Sprintf("%d", totalVulns)))
	fmt.Printf("Total duration:       %s\n", totalDuration.Round(time.Millisecond))
	fmt.Println(strings.Repeat("─", 60))
}

func printJSONResults(results []ProviderResult, totalDuration time.Duration) error {
	output := map[string]interface{}{
		"results":        results,
		"total_duration": totalDuration.String(),
		"timestamp":      time.Now().Format(time.RFC3339),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}

func workspaceDir(workspace, name string) string {
	return filepath.Join(workspace, name)
}
