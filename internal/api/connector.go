package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Oladev-01/safeenv/internal/config"
	"io"
	"net/http"
	"strings"
	"time"
)

type SupabaseClient struct {
	BaseUrl    string
	ServiceKey string
}

// NewClient now returns an error if settings are missing or corrupted
func NewClient() (*SupabaseClient, error) {
	settings, err := config.LoadSettings()
	if err != nil {
		return nil, err // Returns the [Auth Error] or [System Error]
	}

	return &SupabaseClient{
		BaseUrl:    settings.SupabaseURL,
		ServiceKey: settings.ServiceKey,
	}, nil
}

func (c *SupabaseClient) InitDB() error {
	// Security check: Ensure we aren't sending requests with empty credentials
	if c.BaseUrl == "" || c.ServiceKey == "" {
		return fmt.Errorf("[Auth Error] database credentials are empty: run 'safeenv init'")
	}

	req, _ := http.NewRequest("GET", strings.TrimSuffix(c.BaseUrl, "/")+"/rest/v1/", nil)
	req.Header.Set("apikey", c.ServiceKey)

	client := &http.Client{Timeout: 20 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		// Clean error for network glitches
		return fmt.Errorf("[Network Error] failed to reach server: please check your connection")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("[System Error] database rejected connection (Status %d): verify your service key", resp.StatusCode)
	}

	fmt.Println("✅ Service connected to Supabase")
	return nil
}

// MakeDBRequest remains largely the same, but now uses the persistent client data
func (c *SupabaseClient) MakeDBRequest(method string, endpoint string, data interface{}, headers map[string]string) (*http.Response, error) {
	baseUrl := strings.TrimSuffix(c.BaseUrl, "/")
	fullURL := fmt.Sprintf("%s/rest/v1/%s", baseUrl, endpoint)

	var bodyReader io.Reader
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("[System Error] json marshal error: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("[System Error] request creation error: %w", err)
	}

	req.Header.Set("apikey", c.ServiceKey)
	req.Header.Set("Authorization", "Bearer "+c.ServiceKey)
	req.Header.Set("Content-Type", "application/json")

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("[Network Error] server unreachable: check your connection and retry")
	}
	return resp, nil
}