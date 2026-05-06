package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/Oladev-01/safeenv/internal/config" 
)

var (
	joinTeamName string
	joinUsername string
	inviteCode   string
)

func init() {
	// 1. Setup flags
	JoinTeamCmd.Flags().StringVarP(&joinTeamName, "team", "t", "", "Name of the team you want to join (required)")
	JoinTeamCmd.Flags().StringVarP(&joinUsername, "user", "u", "", "Your display name for this team (required)")
	JoinTeamCmd.Flags().StringVarP(&inviteCode, "code", "c", "", "The 6-digit invite code (required)")

	// 2. Mark flags as required
	JoinTeamCmd.MarkFlagRequired("team")
	JoinTeamCmd.MarkFlagRequired("user")
	JoinTeamCmd.MarkFlagRequired("code")

	// 3. Attach to root
	rootCmd.AddCommand(JoinTeamCmd)
}

var JoinTeamCmd = &cobra.Command{
	Use:   "join",
	Short: "Join an existing team using an invite code",
	Long:  `Allows you to become a member of a team. You must provide the exact team name and a valid, non-expired invite code.`,
	Example: "safeenv join -t your_team -u your_username -c 123456",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load session for the current user's ID
		session, err := config.LoadSession()
		if err != nil {
			return fmt.Errorf("[Auth Error] no active session found: please login first")
		}

		userID := session.UserID


		// 2. Execute Join Logic
		fmt.Printf("🔗 Attempting to join team '%s'...\n", joinTeamName)
		
		err = apiClient.JoinTeam(joinTeamName, userID, joinUsername, inviteCode)
		if err != nil {
			// Returns our formatted [Conflict], [Invalid Input], or [System Error]
			return err
		}

		fmt.Printf("✅ Success! You are now a member of '%s'.\n", joinTeamName)
		return nil
	},
}