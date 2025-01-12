// log package configures the log/slog package
package log

import (
	"log/slog"
	"os"

	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/version"
)

// SetDefaultLevel sets the default log level for log/slog.
var SetDefaultLevel = slog.SetLogLoggerLevel

// Setup configures the default logger for log/slog.
func Setup() {
	slog.SetDefault(
		slog.New(
			slog.NewJSONHandler(os.Stderr, nil),
		).WithGroup("krmFunc").With(
			slog.String("name", "sealedsecret-from-1password"),
			slog.String("revision", version.Version()),
		),
	)
}
