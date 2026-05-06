package cmd
import (
	"fmt"
	"github.com/Oladev-01/safeenv/internal/config"
	"os"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
    Use:   "reset",
    Short: "Remove local identity and delete cloud record",
    RunE: func(cmd *cobra.Command, args []string) error {
        session, err := config.LoadSession()
        if err != nil {
            return fmt.Errorf("no session found to reset")
        }

        fmt.Print("⚠️ This will permanently delete your cloud identity. Type 'yes' to confirm: ")
        // Use a simple fmt.Scan to get confirmation
        var confirm string
        fmt.Scanln(&confirm)

        if confirm != "yes" {
            fmt.Println("Reset cancelled.")
            return nil
        }

        // 1. Delete from Supabase first while we still have the ID
        err = apiClient.DeleteUser(session.UserID)
        if err != nil {
            return fmt.Errorf(MsgServerError)
        }

        // 2. Now delete the local file
        path := config.GetConfigPath()
        os.Remove(path)

        fmt.Println("✅ Local and cloud records have been wiped. You can now 'register' again.")
        return nil
    },
}

func init() {
	rootCmd.AddCommand(resetCmd)
}
