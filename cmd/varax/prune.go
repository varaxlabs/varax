package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/varax/operator/pkg/storage"
)

var pruneMaxAge time.Duration

func newPruneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Remove scan results and evidence older than a given age",
		RunE:  runPrune,
	}
	cmd.Flags().DurationVar(&pruneMaxAge, "max-age", 30*24*time.Hour, "remove data older than this duration (e.g. 720h, 30d)")
	return cmd
}

func runPrune(cmd *cobra.Command, args []string) error {
	store, err := storage.NewBoltStore(defaultDBPath())
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer store.Close()

	pruned, err := store.PruneOlderThan(pruneMaxAge)
	if err != nil {
		return fmt.Errorf("prune failed: %w", err)
	}

	if pruned == 0 {
		fmt.Println("No records older than", pruneMaxAge, "found.")
	} else {
		fmt.Printf("Pruned %d record(s) older than %s.\n", pruned, pruneMaxAge)
	}
	return nil
}
