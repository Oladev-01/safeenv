package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/Oladev-01/safeenv/internal/config"
	"github.com/spf13/cobra"
)

// Global or package-level variables linked to flags
var (
	usernames []string
	allFlag   bool
	safeName  string
)

// safeCreateCmd represents the safe create command
var safeCreateCmd = &cobra.Command{
	Use:   "create [file_path]",
	Short: "Encrypt and distribute a secret file to team members",
	Long: `Creates a new safe record by encrypting a local file (such as a .env file) 
using modern Curve25519/X25519 hybrid cryptography. The resulting encrypted 
blob is pushed to the database, and access keys are securely distributed via envelopes.`,
	Example: `  # Share a .env file with the entire dev team (safe name defaults to '.env')
  safeenv create .env --team your-team --all

  # Share a secret file with specific team users and assign a custom safe name
  safeenv create production.json -t your-team -u user1,user2 -n custom-filename

  # Target multiple specific users
  safeenv create .env --team your-team -u user1 -u user2`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// 1. DYNAMIC NAMING LOGIC:
		// If the user didn't explicitly use -n / --name, extract the base filename automatically.
		finalSafeName := safeName
		if finalSafeName == "" {
			finalSafeName = filepath.Base(filePath)
		}

		// 2. Validate session authentication
		session, err := config.LoadSession()
		if err != nil {
			return fmt.Errorf("[Auth Error] no active session found: please login first")
		}

		// 3. Trigger backend cryptographic processing & insertion pipeline
		err = apiClient.CreateSafe(session.UserID, teamName, finalSafeName, usernames, allFlag, filePath)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(safeCreateCmd)

	// Define Flags
	safeCreateCmd.Flags().StringVarP(&teamName, "team", "t", "", "Name of the target team (Required)")
	safeCreateCmd.Flags().BoolVarP(&allFlag, "all", "a", false, "Distribute to all members within the team context")
	safeCreateCmd.Flags().StringSliceVarP(&usernames, "user", "u", []string{}, "Specify explicit usernames to receive access envelopes")
	
	safeCreateCmd.Flags().StringVarP(&safeName, "name", "n", "", "Custom tracking name for the safe (Optional: defaults to file name)")

	// Enforce crucial flag constraints
	safeCreateCmd.MarkFlagRequired("team")
}