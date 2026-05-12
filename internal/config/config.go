package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"github.com/google/uuid"
)

type Config struct {
	UserID    uuid.UUID `json:"user_id"`
	PublicKey string    `json:"public_key"`
}

type Settings struct {
	SupabaseURL string `json:"supabase_url"`
	ServiceKey string `json:"service_key"`
}

// GetConfigPath determines where to store the file (e.g., /home/user/.safeenv/config.json)
func GetConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".safeenv", "config.json")
}

func GetSettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".safeenv", "settings.json")
}

// SaveSession is the function that physically WRITES the data to your hard drive
func SaveSession(id uuid.UUID, pubKey string) error {
	conf := Config{
		UserID:    id,
		PublicKey: pubKey,
	}

	// 1. Convert the Go struct into JSON text
	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return err
	}

	path := GetConfigPath()

	// 2. Create the hidden directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	// 3. Write the file to disk with restricted permissions (0600)
	fmt.Printf("Saving session to %s...\n", path)
	return os.WriteFile(path, data, 0600)
}

// LoadSession is the function that READS the data later
func LoadSession() (*Config, error) {
	path := GetConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no identity found. Please run 'safeenv register' first")
		}
		return nil, err
	}

	var conf Config
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("identity file is corrupted: %w", err)
	}

	return &conf, nil
}

func SaveSettings(url string, key string) error {
	set := Settings {
		SupabaseURL: url,
		ServiceKey: key,
	}

	data, err := json.MarshalIndent(set, "", "")
	if err != nil {
		return err
	}

	path := GetSettingsPath()
	os.MkdirAll(filepath.Dir(path), 0755)
	return os.WriteFile(path, data, 0644)
}

func LoadSettings() (*Settings, error) {
	path := GetSettingsPath()

	data, err := os.ReadFile(path)
	if err != nil {
        if os.IsNotExist(err) {
            return nil, fmt.Errorf("[Auth Error] app not initialized. Please run 'safeenv init' first")
        }
        return nil, fmt.Errorf("[System Error] failed to read settings: %w", err)
    }

	var set Settings
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("[System Error] settings file is corrupted: %w", err)
	}

	return &set, nil
}