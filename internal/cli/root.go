package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile   string
	logLevel  string
	verbose   bool
	outputFmt string
	log       *logrus.Logger
)

// Version information (set by build flags)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "vulnz",
	Short: "Vulnerability data aggregator for 27+ sources",
	Long: `vulnz-go is a Go port of Vunnel, a tool for collecting, transforming, 
and storing vulnerability information from multiple data providers.

It aggregates vulnerability data from OS distributions, language ecosystems,
and security databases into a unified format.`,
	PersistentPreRunE: setupLogging,
	SilenceUsage:      true,
	SilenceErrors:     true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ~/.vulnz.yaml)")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "text", "output format (text, json)")

	// Bind flags to viper
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error finding home directory: %v\n", err)
			os.Exit(1)
		}

		// Search config in home directory and current directory
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vulnz")
	}

	// Read in environment variables that match
	viper.SetEnvPrefix("VULNZ")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Read config file (don't error if not found)
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Using config file: %s\n", viper.ConfigFileUsed())
		}
	}
}

// setupLogging configures the logger based on flags and config
func setupLogging(cmd *cobra.Command, args []string) error {
	log = logrus.New()
	log.SetOutput(os.Stderr)

	// Set log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %s", logLevel)
	}
	log.SetLevel(level)

	// Set formatter
	if outputFmt == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
		})
	}

	return nil
}

// getLogger returns the configured logger
func getLogger() *logrus.Logger {
	if log == nil {
		log = logrus.New()
	}
	return log
}

// colorize returns a colored string based on output format
func colorize(c *color.Color, text string) string {
	if outputFmt == "json" {
		return text
	}
	return c.Sprint(text)
}

// printSuccess prints a success message
func printSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(colorize(color.New(color.FgGreen), "✓ "+msg))
}

// printError prints an error message
func printError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, colorize(color.New(color.FgRed), "✗ "+msg))
}

// printWarning prints a warning message
func printWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, colorize(color.New(color.FgYellow), "⚠ "+msg))
}

// printInfo prints an info message
func printInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(colorize(color.New(color.FgCyan), "ℹ "+msg))
}
