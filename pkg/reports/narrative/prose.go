package narrative

import (
	"fmt"
	"strings"
)

// pluralize returns "1 binding" or "3 bindings".
func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("1 %s", singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}

// joinList returns "A", "A and B", or "A, B, and C" (Oxford comma).
func joinList(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") +
			", and " + items[len(items)-1]
	}
}

// verbAgreement returns "has" for count==1, "have" otherwise.
func verbAgreement(count int) string {
	if count == 1 {
		return "has"
	}
	return "have"
}

// percent computes (part*100)/total, returning 0 if total is 0.
func percent(part, total int) int {
	if total == 0 {
		return 0
	}
	return (part * 100) / total
}

// statusLabel returns a human-friendly status label.
func statusLabel(pass, fail int) string {
	switch {
	case fail == 0 && pass > 0:
		return "PASS"
	case pass == 0 && fail > 0:
		return "FAIL"
	case pass > 0 && fail > 0:
		return "PARTIAL"
	default:
		return "NOT ASSESSED"
	}
}

// countByStatus counts passing and failing checks from findings context.
func countByStatus(passCount, failCount int) string {
	parts := []string{}
	if passCount > 0 {
		parts = append(parts, fmt.Sprintf("%s passing", pluralize(passCount, "check", "checks")))
	}
	if failCount > 0 {
		parts = append(parts, fmt.Sprintf("%s failing", pluralize(failCount, "check", "checks")))
	}
	if len(parts) == 0 {
		return "no checks assessed"
	}
	return strings.Join(parts, " and ")
}
