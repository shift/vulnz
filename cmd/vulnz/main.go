package main

import (
	"fmt"
	"os"

	"github.com/shift/vulnz/internal/cli"
	_ "github.com/shift/vulnz/internal/providers"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
