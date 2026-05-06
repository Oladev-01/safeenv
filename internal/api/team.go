package api
import (
	"github.com/Oladev-01/safeenv/internal/crypto"
	// "github.com/Oladev-01/safeenv/internal/model"
	"github.com/google/uuid"
    "regexp"
	"fmt"
	"net/http"
	"net/url"
	"encoding/json"
	"time"
)

func (c *SupabaseClient) CreateTeamInvite(teamID uuid.UUID) (string, error) {
    // 1. Cryptographic Generation
    rawOTP, hashedOTP, err := crypto.GenerateOTP()
    if err != nil {
        return "", fmt.Errorf("[Security Error] failed to generate secure OTP: %w", err)
    }

    // 2. Prepare Payload
    payload := map[string]interface{}{
        "team_id":    teamID,
        "hashed_otp": hashedOTP,
        "expires_at": time.Now().Add(1 * time.Hour),
    }

    // 3. Persist to Database
    // Note: /rest/v1 is auto-prefixed by MakeDBRequest as requested
    resp, err := c.MakeDBRequest("POST", "team_invites", payload, nil)
    if err != nil {
        return "", fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
    }
    defer resp.Body.Close()

    // 4. Handle Backend Response
    if resp.StatusCode >= 300 {
        // This usually happens if the team_id doesn't exist or RLS blocks the admin
        return "", fmt.Errorf("[System Error] server rejected the invite creation (Status %d): verify team permissions", resp.StatusCode)
    }

    // Return the raw code for the Admin to display in the IDE
    return rawOTP, nil
}

func (c *SupabaseClient) CanUserGenerateInvite(userID uuid.UUID, teamID uuid.UUID) (bool, error) {
    path := fmt.Sprintf("membership?user_id=eq.%s&team_id=eq.%s&select=role", 
        url.QueryEscape(userID.String()), 
        url.QueryEscape(teamID.String()))

    // 1. Handle Network/Request Errors
    resp, err := c.MakeDBRequest("GET", path, nil, nil)
    if err != nil {
        return false, fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
    }
    defer resp.Body.Close()

    // 2. Handle Backend Status Errors
    if resp.StatusCode != http.StatusOK {
        return false, fmt.Errorf("[System Error] backend rejected authorization check (Status %d)", resp.StatusCode)
    }

    // 3. Handle JSON Decoding/Data Integrity
    var results []struct {
        Role string `json:"role"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
        return false, fmt.Errorf("[Data Error] failed to parse authorization response: %v", err)
    }

    // 4. Logical Check (Silent if not a member, as bool handles it)
    if len(results) == 0 {
        return false, nil // Not a member of this team
    }

    return results[0].Role == "admin", nil
}

func (c *SupabaseClient) RunTeamInvite(userID uuid.UUID, teamName string) (string, error) {
	// 1. Resolve Team Name to ID
	path := fmt.Sprintf("teams?name=eq.%s&select=id", url.QueryEscape(teamName))

	resp, err := c.MakeDBRequest("GET", path, nil, nil)
	if err != nil {
		return "", fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("[System Error] backend rejected team lookup (Status %d)", resp.StatusCode)
	}

	var results []struct {
		ID uuid.UUID `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return "", fmt.Errorf("[Data Error] failed to parse team data: %v", err)
	}

	// Handle case where team doesn't exist
	if len(results) == 0 {
		return "", fmt.Errorf("[Invalid Input] team '%s' not found: please check the spelling", teamName)
	}

	teamID := results[0].ID

	// 2. Authorization Check
	isAdmin, err := c.CanUserGenerateInvite(userID, teamID)
	if err != nil {
		// CanUserGenerateInvite already returns IDE-formatted errors
		return "", err 
	}

	if !isAdmin {
		return "", fmt.Errorf("[Auth Error] access denied: only team admins can generate invite codes for '%s'", teamName)
	}

	// 3. Generate and Return the Code
	code, err := c.CreateTeamInvite(teamID)
	if err != nil {
		// CreateTeamInvite already returns IDE-formatted errors
		return "", err
	}

	return code, nil
}

// isValidTeamName checks our security and naming standards
func isValidTeamName(name string) bool {
	// ^[a-zA-Z]      : Starts with a letter
	// [a-zA-Z0-9_]* : Followed by letters, numbers, or underscores
	// $              : End of string
	// Length is checked separately for clarity
	re := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
	return len(name) > 3 && re.MatchString(name)
}

func (c *SupabaseClient) CreateTeam(teamName string, createdByID uuid.UUID, createdByUserName string) error {
	// 1. Client-Side Validation
	if !isValidTeamName(teamName) {
		return fmt.Errorf("[Invalid Input] team name '%s' is invalid: must be > 3 chars, start with a letter, and contain only alphanumeric/underscores", teamName)
	}

	// 2. Create the Team
	teamData := map[string]interface{}{
		"name":       teamName,
		"created_by": createdByID,
	}

	// Use "return=representation" to get the created team's ID back immediately
	headers := map[string]string{"Prefer": "return=representation"}
	resp, err := c.MakeDBRequest("POST", "teams", teamData, headers)
	if err != nil {
		return fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
	}
	defer resp.Body.Close()

	// Handle Name Conflicts (PostgREST returns 409 for unique constraint violations)
	if resp.StatusCode == 409 {
		return fmt.Errorf("[Conflict] team name '%s' is already taken: please choose a unique name", teamName)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("[System Error] unexpected database response while creating team (Status %d)", resp.StatusCode)
	}

	var createdTeams []struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createdTeams); err != nil || len(createdTeams) == 0 {
		return fmt.Errorf("[Data Error] team was created but server failed to return the record ID")
	}
	teamID := createdTeams[0].ID

	// 3. Create the Admin Membership
	memberData := map[string]interface{}{
		"team_id":  teamID,
		"user_id":  createdByID,
		"username": createdByUserName,
		"role":     "admin",
	}

	mResp, err := c.MakeDBRequest("POST", "membership", memberData, nil)
	if err != nil {
		return fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
	}
	defer mResp.Body.Close()

	if mResp.StatusCode >= 300 {
		// This is a partial failure (Team exists, but user isn't admin yet)
		return fmt.Errorf("[Partial Success] team created, but failed to assign admin role: contact support or try manual joining")
	}

	return nil
}


func (c *SupabaseClient) JoinTeam(teamName string, userID uuid.UUID, username string, otp string) error {
	// 1. Resolve Team Name to ID
	path := fmt.Sprintf("teams?name=eq.%s&select=id", url.QueryEscape(teamName))
	resp, err := c.MakeDBRequest("GET", path, nil, nil)
	if err != nil {
		return fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
	}
	defer resp.Body.Close()

	var teams []struct {
		ID uuid.UUID `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&teams)

	if len(teams) == 0 {
		return fmt.Errorf("[Invalid Input] team '%s' not found: check the spelling or ask your admin for the correct name", teamName)
	}
	teamID := teams[0].ID

	// 2. Verify OTP against an ACTIVE, UNUSED invite
	// Filter: must match team_id, is_used must be false, and not expired
	invitePath := fmt.Sprintf("team_invites?team_id=eq.%s&is_used=eq.false&expires_at=gt.now()&select=id,hashed_otp", 
		url.QueryEscape(teamID.String()))
	
	iResp, err := c.MakeDBRequest("GET", invitePath, nil, nil)
	if err != nil {
		return fmt.Errorf("[Network Error] connection unstable: please check your internet and try again")
	}
	defer iResp.Body.Close()

	var invites []struct {
		ID        uuid.UUID `json:"id"`
		HashedOTP string    `json:"hashed_otp"`
	}
	json.NewDecoder(iResp.Body).Decode(&invites)

	if len(invites) == 0 {
		return fmt.Errorf("[Security Error] no active invite found for team '%s': ask your admin to generate a new code", teamName)
	}

	// 3. Perform Cryptographic Verification
	inviteMatch := false
	var successfulInviteID uuid.UUID
	
	for _, inv := range invites {
		if crypto.VerifyOTP(otp, inv.HashedOTP) {
			inviteMatch = true
			successfulInviteID = inv.ID
			break
		}
	}

	if !inviteMatch {
		return fmt.Errorf("[Auth Error] invalid invite code: the OTP you entered is incorrect")
	}

	// 4. Create Membership
	memberData := map[string]interface{}{
		"team_id":  teamID,
		"user_id":  userID,
		"username": username,
		"role":     "member",
	}

	mResp, err := c.MakeDBRequest("POST", "membership", memberData, nil)
	if err != nil {
		return fmt.Errorf("[System Error] failed to create membership: %w", err)
	}
	defer mResp.Body.Close()

	if mResp.StatusCode == 409 {
		return fmt.Errorf("[Conflict] username '%s' is already taken in this team: please choose a different alias", username)
	}
	if mResp.StatusCode >= 300 {
		return fmt.Errorf("[System Error] unexpected database response (Status %d)", mResp.StatusCode)
	}

	// 5. "Burn" the invite code so it can't be used again
	patchPath := fmt.Sprintf("team_invites?id=eq.%s", successfulInviteID)
	c.MakeDBRequest("PATCH", patchPath, map[string]bool{"is_used": true}, nil)

	return nil
}