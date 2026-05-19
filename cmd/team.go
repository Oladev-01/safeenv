package cmd

import "github.com/spf13/cobra"

// teamCmd acts as the 'team' namespace
var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Manage team security contexts",
}

func init() {
	// We attach 'team' directly to 'safeenv'
	rootCmd.AddCommand(teamCmd)
}