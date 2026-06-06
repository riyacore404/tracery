package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/riyacore/tracery/internal/logger"
)

var (
	verbose bool
	pretty  bool
)

var rootCmd = &cobra.Command{
	Use:   "tracery",
	Short: "eBPF-based syscall and performance tracer",
	Long: `Tracery attaches invisible probes to any Linux process
and streams syscall traces, latency measurements, and memory
events in real-time — with under 3% overhead.`,

	// PersistentPreRun runs before every subcommand
	// This is where we initialize logging before anything else
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(pretty, verbose)
		log.Debug().Msg("tracery starting")
	},
}

func main() {
	// Global flags available to all subcommands
	rootCmd.PersistentFlags().BoolVarP(
		&verbose, "verbose", "v", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(
		&pretty, "pretty", true, "human-readable log output")

	rootCmd.AddCommand(countCmd)
	rootCmd.AddCommand(latencyCmd)
	rootCmd.AddCommand(eventsCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}