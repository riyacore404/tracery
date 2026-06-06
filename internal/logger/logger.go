package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init sets up the global logger.
// pretty=true gives human-readable output for terminals.
// pretty=false gives JSON output for log aggregators (production).
func Init(pretty bool, verbose bool) {
	level := zerolog.InfoLevel
	if verbose {
		level = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(level)
	zerolog.TimeFieldFormat = time.RFC3339

	if pretty {
		// Human-readable: timestamp + level + message
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
		})
	}
	// If not pretty, zerolog defaults to JSON — good for prod
}
