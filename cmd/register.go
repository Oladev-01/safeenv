package cmd

import (
	"fmt"
	"github.com/Oladev-01/safeenv/internal/crypto"
	"github.com/Oladev-01/safeenv/internal/ui"
	"github.com/spf13/cobra"
	"github.com/Oladev-01/safeenv/internal/config"
)



func init() {
	// Attach 'register' to the main 'safeenv' command
	rootCmd.AddCommand(registerCmd)
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Onboard a new user by creating a cryptographic identity",
	SilenceErrors: true,
	// SilenceUsage prevents the "Help" text from printing every time there's a network error
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		existingSession, err := config.LoadSession()
		if err == nil && existingSession != nil {
			fmt.Println("ℹ️  You are already registered on this machine!")
			fmt.Printf("User ID: %s\n", existingSession.UserID)
			fmt.Println("\n👉 To safely wipe your data and start over, run:")
    		fmt.Println("   safeenv reset")
			return nil // Exit early
		}

		// 1. Get Passphrase
		pass, err := ui.GetValidatedPassphrase()
		if err != nil {
			return fmt.Errorf(MsgServerError)
		}

		// 2. Generate Identity
		identity, err := crypto.CreateNewIdentity(pass)
		if err != nil {
			return fmt.Errorf(MsgServerError)
		}

		// 3. Register with Supabase
		// Passing the identity directly as you requested
		userID, err := apiClient.RegisterIdentity(identity)
		if err != nil {
			return fmt.Errorf("❌ Registration failed: %w", err)
		}

		if err := config.SaveSession(*userID, identity.PublicKey); err != nil {
			return fmt.Errorf("failed to link identity locally")
		}

		fmt.Println("✅ User successfully registered")
		return nil
	},
}