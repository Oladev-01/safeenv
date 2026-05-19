package cmd

import "github.com/spf13/cobra"


var safeCmd = &cobra.Command{
	Use: "safe",
	Short: "Create, retrieve, and manage secure environments",
}


func init() {
	rootCmd.AddCommand(safeCmd)
}