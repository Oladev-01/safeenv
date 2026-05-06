package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/Oladev-01/safeenv/internal/config"
)

var (
	targetTeam string
)

func init() {
	// 1. Setup flags
	InviteCmd.Flags().StringVarP(&targetTeam, "team", "t", "", "Name of the team you want to generate a code for (required)")

	// 2. Mark as required
	InviteCmd.MarkFlagRequired("team")

	// 3. Attach to root
	rootCmd.AddCommand(InviteCmd)
}

var InviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Generate a one-time invite code for a team",
	Long:  `Generates a secure, 1-hour valid OTP that allows another user to join your team. 
You must be an Admin of the team to run this command.`,
	Example: "safeenv invite -t your_team",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load session for the current user's ID
		session, err := config.LoadSession()
		if err != nil {
			return fmt.Errorf("[Auth Error] no active session found: please login first")
		}

		// Since session.UserID is already uuid.UUID
		userID := session.UserID

		// 2. Run the orchestration logic
		fmt.Printf("🔑 Generating invite code for '%s'...\n", targetTeam)
		
		code, err := apiClient.RunTeamInvite(userID, targetTeam)
		if err != nil {
			// This will return our formatted [Auth Error] if they aren't an admin
			return err
		}

		// 4. Output the code clearly for the user to copy
		fmt.Println("-------------------------------------------")
		fmt.Printf("✅ Invite generated! Share this code:\n\n")
		fmt.Printf("    %s\n\n", code)
		fmt.Println("Note: This code expires in 1 hour.")
		fmt.Println("-------------------------------------------")
		
		return nil
	},
}