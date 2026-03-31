package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show or validate configuration",
	Long: `Show current configuration or validate a configuration file.

Configuration can come from multiple sources (in order of precedence):
  1. Command-line flags
  2. Environment variables (prefixed with VULNZ_)
  3. Configuration file (~/.vulnz.yaml or specified with --config)

Examples:
  # Show current configuration
  vulnz config show

  # Validate configuration file
  vulnz config validate

  # Validate specific config file
  vulnz config validate --config /path/to/config.yaml`,
}

// configShowCmd shows the current configuration
var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	Long:  `Display the current configuration with all settings and their sources.`,
	RunE:  runConfigShow,
}

// configValidateCmd validates the configuration
var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	Long: `Validate the configuration file for syntax errors and required fields.

Returns exit code 0 if valid, non-zero if invalid.`,
	RunE: runConfigValidate,
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configValidateCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	// Get config file being used
	configFile := viper.ConfigFileUsed()
	if configFile == "" {
		configFile = "none (using defaults)"
	}

	if outputFmt == "json" {
		return printConfigJSON()
	}

	// Print header
	fmt.Println()
	fmt.Println(colorize(color.New(color.FgWhite, color.Bold), "Configuration"))
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Printf("Config file: %s\n\n", colorize(color.New(color.FgCyan), configFile))

	// Print settings by section
	printConfigSection("Logging", []ConfigItem{
		{Key: "log.level", Value: viper.GetString("log.level")},
		{Key: "log.verbose", Value: viper.GetBool("log.verbose")},
		{Key: "log.slim", Value: viper.GetBool("log.slim")},
		{Key: "log.show_timestamp", Value: viper.GetBool("log.show_timestamp")},
		{Key: "log.show_level", Value: viper.GetBool("log.show_level")},
	})

	printConfigSection("Workspace", []ConfigItem{
		{Key: "root", Value: viper.GetString("root")},
	})

	printConfigSection("Executor", []ConfigItem{
		{Key: "executor.max_concurrent", Value: viper.GetInt("executor.max_concurrent")},
		{Key: "executor.timeout", Value: viper.GetString("executor.timeout")},
	})

	// Provider configurations
	if viper.IsSet("providers") {
		providers := viper.GetStringMap("providers")
		fmt.Println()
		fmt.Println(colorize(color.New(color.FgYellow, color.Bold), "Providers"))
		fmt.Println("─────────────────────────────────────────────────────────────")

		for name := range providers {
			if name == "common" {
				continue
			}
			fmt.Printf("  %s:\n", colorize(color.New(color.FgCyan), name))

			// Show runtime config
			runtimeStore := viper.GetString(fmt.Sprintf("providers.%s.runtime.result_store", name))
			if runtimeStore != "" {
				fmt.Printf("    result_store: %s\n", runtimeStore)
			}

			existingResults := viper.GetString(fmt.Sprintf("providers.%s.runtime.existing_results", name))
			if existingResults != "" {
				fmt.Printf("    existing_results: %s\n", existingResults)
			}

			// Show any other custom fields
			// (This is simplified - a real implementation would inspect the full provider config)
		}
	}

	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	printInfo("Use 'vulnz config validate' to check configuration validity")

	return nil
}

// ConfigItem represents a configuration key-value pair
type ConfigItem struct {
	Key   string
	Value interface{}
}

// printConfigSection prints a section of configuration
func printConfigSection(title string, items []ConfigItem) {
	fmt.Println()
	fmt.Println(colorize(color.New(color.FgYellow, color.Bold), title))
	fmt.Println("─────────────────────────────────────────────────────────────")

	for _, item := range items {
		value := item.Value
		if value == nil || value == "" || value == 0 || value == false {
			value = colorize(color.New(color.FgHiBlack), "(not set)")
		}
		fmt.Printf("  %-25s %v\n", item.Key+":", value)
	}
}

// printConfigJSON outputs configuration as JSON
func printConfigJSON() error {
	settings := viper.AllSettings()
	encoder := yaml.NewEncoder(os.Stdout)
	encoder.SetIndent(2)
	return encoder.Encode(settings)
}

func runConfigValidate(cmd *cobra.Command, args []string) error {
	configFile := viper.ConfigFileUsed()

	if configFile == "" {
		printWarning("No configuration file found")
		printInfo("Checked locations:")
		fmt.Println("  • ~/.vulnz.yaml")
		fmt.Println("  • ./.vulnz.yaml")
		return nil
	}

	// Try to read and parse the config file
	data, err := os.ReadFile(configFile)
	if err != nil {
		printError("Failed to read config file: %v", err)
		return err
	}

	// Validate YAML syntax
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		printError("Invalid YAML syntax: %v", err)
		return err
	}

	// Validate required fields and values
	errors := validateConfig(config)

	if len(errors) > 0 {
		printError("Configuration validation failed:")
		for _, err := range errors {
			fmt.Printf("  • %s\n", err)
		}
		return fmt.Errorf("validation failed with %d error(s)", len(errors))
	}

	printSuccess("Configuration is valid: %s", configFile)
	return nil
}

// validateConfig performs semantic validation of configuration
func validateConfig(config map[string]interface{}) []string {
	errors := []string{}

	// Validate log level
	if logCfg, ok := config["log"].(map[string]interface{}); ok {
		if level, ok := logCfg["level"].(string); ok {
			validLevels := map[string]bool{
				"debug": true,
				"info":  true,
				"warn":  true,
				"error": true,
			}
			if !validLevels[level] {
				errors = append(errors, fmt.Sprintf("invalid log level: %s (must be debug, info, warn, or error)", level))
			}
		}
	}

	// Validate executor settings
	if execCfg, ok := config["executor"].(map[string]interface{}); ok {
		if maxConc, ok := execCfg["max_concurrent"].(int); ok {
			if maxConc < 1 || maxConc > 100 {
				errors = append(errors, fmt.Sprintf("invalid executor.max_concurrent: %d (must be between 1 and 100)", maxConc))
			}
		}
	}

	// Validate provider configurations
	if providersCfg, ok := config["providers"].(map[string]interface{}); ok {
		for name, pCfg := range providersCfg {
			if name == "common" {
				continue
			}

			if providerMap, ok := pCfg.(map[string]interface{}); ok {
				// Validate runtime settings
				if runtime, ok := providerMap["runtime"].(map[string]interface{}); ok {
					// Validate result_store
					if store, ok := runtime["result_store"].(string); ok {
						if store != "flat-file" && store != "sqlite" {
							errors = append(errors, fmt.Sprintf("invalid providers.%s.runtime.result_store: %s (must be 'flat-file' or 'sqlite')", name, store))
						}
					}

					// Validate existing_results
					if existing, ok := runtime["existing_results"].(string); ok {
						validPolicies := map[string]bool{
							"keep":                true,
							"delete":              true,
							"delete-before-write": true,
						}
						if !validPolicies[existing] {
							errors = append(errors, fmt.Sprintf("invalid providers.%s.runtime.existing_results: %s (must be 'keep', 'delete', or 'delete-before-write')", name, existing))
						}
					}
				}
			}
		}
	}

	return errors
}
