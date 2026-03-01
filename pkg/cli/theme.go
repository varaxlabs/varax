package cli

import (
	"os"

	"golang.org/x/term"
)

// OutputFormat represents the output format type.
type OutputFormat string

const (
	FormatStyled OutputFormat = "styled"
	FormatPlain  OutputFormat = "plain"
	FormatJSON   OutputFormat = "json"
)

// IsTTY returns true if stdout is a terminal.
func IsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// ResolveFormat returns the effective output format.
// If the user explicitly requested a format, use that.
// Otherwise, default to styled for TTY or plain for non-TTY.
func ResolveFormat(requested string) OutputFormat {
	switch requested {
	case "json":
		return FormatJSON
	case "plain":
		return FormatPlain
	case "styled":
		return FormatStyled
	default:
		if IsTTY() {
			return FormatStyled
		}
		return FormatPlain
	}
}
