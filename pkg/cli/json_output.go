package cli

import (
	"encoding/json"
	"fmt"
)

// RenderJSON marshals any value to indented JSON and prints it.
func RenderJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}
