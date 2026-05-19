package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/Oladev-01/safeenv/internal/config"
)

var (
	teamName string
	username string
)

func init() {
	// 1. Setup flags
	CreateTeamCmd.Flags().StringVarP(&teamName, "team", "t", "", "Name of the team to create (required)")
	CreateTeamCmd.Flags().StringVarP(&username, "user", "u", "", "Your display name within this team (required)")

	// 2. Mark flags as required so Cobra handles the "missing flag" error for us
	CreateTeamCmd.MarkFlagRequired("team")
	CreateTeamCmd.MarkFlagRequired("user")

	// 3. Attach to root
	teamCmd.AddCommand(CreateTeamCmd)
}

var CreateTeamCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new secure team environment",
	Long:  `Initializes a new team in SafeEnv and sets you as the team Admin. 
Requires a unique team name and a username for your team profile.`,
	Example: "safeenv team create -t your_team -u your_username",
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Load local session to get UserID
		session, err := config.LoadSession()
		if err != nil {
			return fmt.Errorf("[Auth Error] no active session found: please login first using 'safeenv login'")
		}

		// Parse the ID from session (assuming it's stored as a string or uuid)
		userID := session.UserID

		// 2. Execute the SDK function
		fmt.Printf("🚀 Creating team '%s'...\n", teamName)
		err = apiClient.CreateTeam(teamName, userID, username)
		if err != nil {
			// This returns our IDE-formatted errors ([Conflict], [Network Error], etc.)
			return err
		}

		fmt.Printf("✅ Success! Team '%s' created and you have been assigned as Admin.\n", teamName)
		return nil
	},
}