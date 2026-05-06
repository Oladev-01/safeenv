package cmd

import (
	"fmt"
	"os"

	"github.com/Oladev-01/safeenv/internal/api"
	"github.com/spf13/cobra"
)

var (
	apiClient *api.SupabaseClient // Shared client
	MsgServerError = "❌ An unexpected error occurred. Please try again."
)

var rootCmd = &cobra.Command{
	Use:   "safeenv",
	Short: "SafeEnv - Secure environment variables management",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// 1. FAST TRACK: Skip DB initialization for help commands
		// This makes './safeenv help' or '--help' instant.
		if cmd.Name() == "help" || cmd.HasParent() && cmd.Parent().Name() == "help" {
			return nil
		}

		if cmd.Name() == "init" {
        	return nil
    	}

		apiClient, err := api.NewClient()
		if err != nil {
			return err
		}
		if err := apiClient.InitDB(); err != nil {
			return fmt.Errorf("❌ Failed to connect to database. Please check your connection")
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}