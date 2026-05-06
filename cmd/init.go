package cmd

import (
	"fmt"
	"github.com/Oladev-01/safeenv/internal/config"
	"github.com/Oladev-01/safeenv/internal/api"
	"github.com/spf13/cobra"
)

func init() {
	// Attach to the root command
	rootCmd.AddCommand(initCmd)
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize SafeEnv with your Supabase credentials",
	Long: `Set up the connection between this CLI and your Supabase backend. 
You will need your Project URL and the service_role secret key from your Supabase dashboard.`,
	Example: "safeenv init",
	RunE: func(cmd *cobra.Command, args []string) error {
		var url, key string

		fmt.Println("🚀 SafeEnv Setup")
		fmt.Println("-------------------------------------------")
		
		// 1. Capture the Supabase URL
		fmt.Print("Enter Supabase Project URL (e.g., https://xyz.supabase.co): ")
		fmt.Scanln(&url)
		if url == "" {
			return fmt.Errorf("[Invalid Input] Project URL cannot be empty")
		}

		// 2. Capture the Service Role Key
		fmt.Print("Enter Supabase Service Role Key: ")
		fmt.Scanln(&key)
		if key == "" {
			return fmt.Errorf("[Invalid Input] Service Role Key cannot be empty")
		}

		// 3. Save to settings.json
		err := config.SaveSettings(url, key)
		if err != nil {
			return fmt.Errorf("[System Error] failed to save configuration: %w", err)
		}

		fmt.Println("Testing connection...")
        client, err := api.NewClient() 
        if err != nil {
            return err
        }

        if err := client.InitDB(); err != nil {
            return err
        }

		fmt.Println("-------------------------------------------")
		fmt.Println("✅ Configuration saved successfully!")
		fmt.Println("You can now run 'safeenv register' or 'safeenv login' to begin.")
		
		return nil
	},
}