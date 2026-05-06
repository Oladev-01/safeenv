package api

import (
	"encoding/json"
	"fmt"
	"io"
	"github.com/google/uuid"
	"github.com/Oladev-01/safeenv/internal/model"
)

// RegisterIdentity saves the crypto vault to the users table
func (c *SupabaseClient) RegisterIdentity(user *models.Users) (*uuid.UUID, error) {
    // 1. Set headers to tell Supabase to return the created object
    headers := map[string]string{
        "Prefer": "return=representation",
    }

    // 2. Make the request
    resp, err := c.MakeDBRequest("POST", "users", user, headers)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // 3. Handle error status codes
    if resp.StatusCode >= 400 {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("server returned error %d: %s", resp.StatusCode, string(body))
    }

    // 4. Decode the response body
    // Supabase returns an array of objects when 'return=representation' is used
    var result []models.Users
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("error decoding result: %w", err)
    }

    // 5. Safety check: Ensure we actually got a record back
    if len(result) == 0 {
        return nil, fmt.Errorf("no user data returned from server")
    }

    // 6. Return the address of the ID
    // result[0].ID is expected to be of type uuid.UUID in your models package
    userID := result[0].ID
    return userID, nil
}

func (c *SupabaseClient) DeleteUser(userID uuid.UUID) error {
    endpoint := fmt.Sprintf("users?id=eq.%s", userID.String())
    resp, err := c.MakeDBRequest("DELETE", endpoint, nil, nil)
    if err != nil {
        return fmt.Errorf("failed to reach database: %w", err)
    }
    defer resp.Body.Close()

    // 3. Check for success (Supabase returns 204 No Content for successful deletes)
    if resp.StatusCode >= 300 {
        return fmt.Errorf("database returned error: status %d", resp.StatusCode)
    }

    return nil
}