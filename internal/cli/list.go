package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"log/slog"

	"github.com/shift/vulnz/internal/provider"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	listWorkspace string
	listTags      []string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available providers",
	Long: `List all registered vulnerability data providers with their metadata.

Shows provider name, description, tags, and last run information if available.

Examples:
  # List all providers
  vulnz list

  # List providers with specific tags
  vulnz list --tags os,linux

  # List with JSON output
  vulnz list --output json`,
	RunE: runList,
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVarP(&listWorkspace, "workspace", "w", "./data", "workspace directory")
	listCmd.Flags().StringSliceVar(&listTags, "tags", []string{}, "filter by tags (comma-separated)")
}

func runList(cmd *cobra.Command, args []string) error {
	names := provider.List()
	providers := make([]ProviderMetadata, 0, len(names))

	for _, name := range names {
		factory, ok := provider.Get(name)
		if !ok {
			continue
		}

		slogLogger := slogDefault()
		config := provider.Config{
			Name:      name,
			Workspace: filepath.Join(listWorkspace, name),
			Logger:    slogLogger,
			HTTP:      provider.DefaultHTTPConfig(),
		}

		inst, err := factory(config)
		if err != nil {
			continue
		}

		meta := ProviderMetadata{Name: name}

		if mp, ok := inst.(provider.MetadataProvider); ok {
			m := mp.Metadata()
			meta.Description = m.Description
		}

		if tp, ok := inst.(provider.TagsProvider); ok {
			meta.Tags = tp.Tags()
		}

		status := loadProviderStatus(&meta, listWorkspace)
		if status != nil {
			meta.LastRun = status.LastRun
			meta.Status = status.State
			meta.Count = status.VulnCount
		}

		providers = append(providers, meta)
	}

	if len(listTags) > 0 {
		providers = filterProvidersByTags(providers, listTags)
	}

	sort.Slice(providers, func(i, j int) bool {
		return providers[i].Name < providers[j].Name
	})

	if outputFmt == "json" {
		return printProvidersJSON(providers)
	}

	printProvidersTable(providers)
	return nil
}

type ProviderMetadata struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Tags        []string  `json:"tags"`
	LastRun     time.Time `json:"last_run,omitempty"`
	Status      string    `json:"status,omitempty"`
	Count       int       `json:"count,omitempty"`
}

type ProviderStatus struct {
	LastRun   time.Time
	State     string
	VulnCount int
}

func loadProviderStatus(p *ProviderMetadata, workspace string) *ProviderStatus {
	metadataPath := filepath.Join(workspace, p.Name, "metadata.json")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return nil
	}
	return nil
}

func filterProvidersByTags(providers []ProviderMetadata, tags []string) []ProviderMetadata {
	filtered := []ProviderMetadata{}

	for _, prov := range providers {
		hasTag := false
		for _, tag := range tags {
			for _, ptag := range prov.Tags {
				if strings.EqualFold(ptag, tag) {
					hasTag = true
					break
				}
			}
			if hasTag {
				break
			}
		}
		if hasTag {
			filtered = append(filtered, prov)
		}
	}

	return filtered
}

func printProvidersTable(providers []ProviderMetadata) {
	if len(providers) == 0 {
		printWarning("No providers found")
		return
	}

	fmt.Println()
	fmt.Println(colorize(color.New(color.FgWhite, color.Bold), "Available Providers"))
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%-25s %-35s %-15s %s\n",
		colorize(color.New(color.FgCyan, color.Bold), "PROVIDER"),
		colorize(color.New(color.FgCyan, color.Bold), "DESCRIPTION"),
		colorize(color.New(color.FgCyan, color.Bold), "TAGS"),
		colorize(color.New(color.FgCyan, color.Bold), "LAST RUN"),
	)
	fmt.Println(strings.Repeat("─", 80))

	for _, p := range providers {
		tags := strings.Join(p.Tags, ",")
		if len(tags) > 15 {
			tags = tags[:12] + "..."
		}

		lastRun := "never"
		if !p.LastRun.IsZero() {
			lastRun = formatTimeAgo(p.LastRun)
		}

		desc := p.Description
		if len(desc) > 35 {
			desc = desc[:32] + "..."
		}

		nameColor := color.New(color.FgWhite)
		if !p.LastRun.IsZero() {
			nameColor = color.New(color.FgGreen)
		}

		fmt.Printf("%-25s %-35s %-15s %s\n",
			colorize(nameColor, p.Name),
			desc,
			tags,
			lastRun,
		)
	}

	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("\nTotal: %s providers\n\n", colorize(color.New(color.FgCyan, color.Bold), fmt.Sprintf("%d", len(providers))))

	printInfo("Run a provider with: vulnz run <provider>")
}

func printProvidersJSON(providers []ProviderMetadata) error {
	output := map[string]interface{}{
		"providers": providers,
		"count":     len(providers),
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)

	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		minutes := int(duration.Minutes())
		return fmt.Sprintf("%dm ago", minutes)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		return fmt.Sprintf("%dh ago", hours)
	} else if duration < 7*24*time.Hour {
		days := int(duration.Hours() / 24)
		return fmt.Sprintf("%dd ago", days)
	} else if duration < 30*24*time.Hour {
		weeks := int(duration.Hours() / 24 / 7)
		return fmt.Sprintf("%dw ago", weeks)
	} else if duration < 365*24*time.Hour {
		months := int(duration.Hours() / 24 / 30)
		return fmt.Sprintf("%dmo ago", months)
	} else {
		years := int(duration.Hours() / 24 / 365)
		return fmt.Sprintf("%dy ago", years)
	}
}

func slogDefault() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}
