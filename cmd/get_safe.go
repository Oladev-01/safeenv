package cmd

import (
	"fmt"
	"os"

	"github.com/Oladev-01/safeenv/internal/config"
	"github.com/spf13/cobra"
)

var (
	getVersion  int
	outputFile  string
)

// safeGetCmd represents the safe get pulling execution utility
var safeGetCmd = &cobra.Command{
	Use:   "pull [safe_name]",
	Short: "Retrieve and decrypt a distributed safe file record",
	Long: `Fetches an encrypted vault envelope from the specified team context.
It automatically verifies team membership status, prompts for your master passphrase, 
and reconstructs the decrypted secret environment file directly into an output path.`,
	Example: `  # Pull the absolute latest release version of a safe file config
  safeenv safe pull production.env --team your-team --output .env

  # Request a historic specific version snapshot index configuration target
  safeenv safe pull production.env -t your-team --version 3 -o decrypted.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetSafeName := args[0]

		// 1. Authenticate context extraction
		session, err := config.LoadSession()
		if err != nil {
			return fmt.Errorf("[Auth Error] no active session found: please login first")
		}

		// 2. Fetch data payload contents and execute asymmetric decryption mechanics
		decryptedContent, err := apiClient.GetSafe(session.UserID, teamName, targetSafeName, getVersion)
		if err != nil {
			return err
		}

		// 3. Define where to save the cleartext file contents output stream destination
		destinationPath := outputFile
		if destinationPath == "" {
			destinationPath = targetSafeName // Fallback to safe name if no output path provided
		}

		// Write cleartext data safely back to disk
		err = os.WriteFile(destinationPath, decryptedContent, 0600) // Owner Read/Write permission exclusively
		if err != nil {
			return fmt.Errorf("[File Error] failed to write decrypted file output stream: %v", err)
		}

		fmt.Printf("💾 Saved to:    %s\n", destinationPath)
		return nil
	},
}

func init() {
	safeCmd.AddCommand(safeGetCmd)

	// Command Flags mapping assignments
	safeGetCmd.Flags().StringVarP(&teamName, "team", "t", "", "Name of the target team (Required)")
	safeGetCmd.Flags().IntVarP(&getVersion, "version", "v", 0, "Specific target version index tracker snapshot (Optional: defaults to latest)")
	safeGetCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Explicit local tracking file destination path to write down (Optional)")

	// Enforce context target matching validation configurations
	safeGetCmd.MarkFlagRequired("team")
}