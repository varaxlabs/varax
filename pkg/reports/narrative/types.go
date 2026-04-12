package narrative

import (
	"fmt"
	"strings"
)

// NarrativeSection is a single paragraph or block in a control narrative.
// Empty Body means the section is omitted from rendering.
type NarrativeSection struct {
	Body  string
	Items []string // If non-empty, renders as a styled list instead of a paragraph
}

// ControlNarrative produces the prose sections for a single SOC2 control.
type ControlNarrative interface {
	Sections() []NarrativeSection
}

// BindingDetail describes a single cluster-admin binding subject.
type BindingDetail struct {
	Name    string
	Subject string
	Type    string // "Group", "User", "ServiceAccount"
}

// Finding represents a check-level finding for narrative prose.
type Finding struct {
	CheckID  string
	Severity string
	Message  string
}

// findingsSection builds a NarrativeSection with findings as a styled list.
// When multiple checks from different benchmarks flag the same underlying issue
// (detected by overlapping resource names in the message), the section annotates
// the corroboration so auditors understand these are independent confirmations.
func findingsSection(findings []Finding) NarrativeSection {
	if len(findings) == 0 {
		return NarrativeSection{}
	}

	// Detect corroborating findings: group by normalized message content
	type group struct {
		checkIDs []string
		message  string
	}
	groups := groupCorroboratingFindings(findings)

	var items []string
	for _, g := range groups {
		if len(g.checkIDs) > 1 {
			items = append(items, fmt.Sprintf("%s: %s (%d independent checks confirm this finding)",
				joinList(g.checkIDs), g.message, len(g.checkIDs)))
		} else {
			items = append(items, g.checkIDs[0]+": "+g.message)
		}
	}

	return NarrativeSection{
		Body:  "Findings requiring attention:",
		Items: items,
	}
}

// groupCorroboratingFindings identifies findings from different checks that
// flag the same underlying issue by comparing the resource names mentioned
// in their messages. Two findings corroborate when they share at least two
// resource names (to avoid false matches on common words).
func groupCorroboratingFindings(findings []Finding) []struct {
	checkIDs []string
	message  string
} {
	type entry struct {
		checkID string
		message string
		words   map[string]bool
	}

	entries := make([]entry, len(findings))
	for i, f := range findings {
		words := make(map[string]bool)
		for _, w := range strings.Fields(f.Message) {
			// Only consider words that look like resource names (contain
			// hyphens, dots, or start with uppercase) to avoid matching
			// on common words like "use" or "permissions"
			if len(w) > 3 && (strings.ContainsAny(w, "-.") || (w[0] >= 'A' && w[0] <= 'Z') || strings.Contains(w, "_")) {
				words[strings.TrimRight(w, ".,;:")] = true
			}
		}
		entries[i] = entry{checkID: f.CheckID, message: f.Message, words: words}
	}

	used := make([]bool, len(entries))
	var groups []struct {
		checkIDs []string
		message  string
	}

	for i := range entries {
		if used[i] {
			continue
		}
		g := struct {
			checkIDs []string
			message  string
		}{
			checkIDs: []string{entries[i].checkID},
			message:  entries[i].message,
		}
		used[i] = true

		for j := i + 1; j < len(entries); j++ {
			if used[j] {
				continue
			}
			// Count shared resource-like words
			shared := 0
			for w := range entries[i].words {
				if entries[j].words[w] {
					shared++
				}
			}
			if shared >= 2 {
				g.checkIDs = append(g.checkIDs, entries[j].checkID)
				used[j] = true
			}
		}
		groups = append(groups, g)
	}
	return groups
}

// MinimalNarrative provides a simple narrative for controls with thin scan coverage.
type MinimalNarrative struct {
	Summary    string
	Assessment string
}

// Sections implements ControlNarrative for MinimalNarrative.
func (n MinimalNarrative) Sections() []NarrativeSection {
	var sections []NarrativeSection
	if n.Summary != "" {
		sections = append(sections, NarrativeSection{Body: n.Summary})
	}
	if n.Assessment != "" {
		sections = append(sections, NarrativeSection{Body: n.Assessment})
	}
	return sections
}
