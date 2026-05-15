package api
import (
	"github.com/Oladev-01/safeenv/internal/crypto"
	"github.com/Oladev-01/safeenv/internal/model"
	"fmt"
    "encoding/base64"
    "golang.org/x/crypto/nacl/box"
    "golang.org/x/term"
	"os"
	"io"
    "github.com/google/uuid"
    "syscall"
	"slices"
	"encoding/json"
	"crypto/rand"
)


func (s *SupabaseClient) FetchTeamMembersWithPublicKeys(teamName string) ([]models.MemberWithKey, string, error) {
    query := fmt.Sprintf("select=team_id,user_id,username,users(public_key),teams!inner(name)&teams.name=eq.%s", teamName)
    endpoint := "membership?" + query

    resp, err := s.MakeDBRequest("GET", endpoint, nil, nil)
    if err != nil {
        return nil, "", fmt.Errorf("[Database Error] request failed: %v", err)
    }
    defer resp.Body.Close()

    bodyBytes, _ := io.ReadAll(resp.Body)

    if resp.StatusCode >= 400 {
        var apiErr struct {
            Message string `json:"message"`
        }
        json.Unmarshal(bodyBytes, &apiErr)
        return nil, "", fmt.Errorf("[Database Error] %s", apiErr.Message)
    }

    var results []struct {
        TeamID   string `json:"team_id"`
        UserID   string `json:"user_id"`
        Username string `json:"username"`
        Users    struct {
            PublicKey string `json:"public_key"`
        } `json:"users"`
    }

    if err := json.Unmarshal(bodyBytes, &results); err != nil {
        return nil, "", fmt.Errorf("[Database Error] failed to decode membership: %v", err)
    }

    if len(results) == 0 {
        return nil, "", fmt.Errorf("[Validation Error] no members found for team '%s'", teamName)
    }

    teamID := results[0].TeamID
    var members []models.MemberWithKey
    for _, r := range results {
        members = append(members, models.MemberWithKey{
            ID:        r.UserID,
            Username:  r.Username,
            PublicKey: r.Users.PublicKey,
        })
    }

    return members, teamID, nil
}


// CreateSafe implements the Phase 4 logic for targeted or team-wide encryption
func (s *SupabaseClient) CreateSafe(senderID uuid.UUID, teamName string, safeName string, usernames []string, all bool, filePath string) error {
    // 1. Resolve Team and Fetch Public Keys (using name-based filtering)
    members, teamID, err := s.FetchTeamMembersWithPublicKeys(teamName)
    if err != nil {
        return err
    }

    isTeamMember := false
	for _, member := range members {
		if member.ID == senderID.String() {
			isTeamMember = true
			break
		}
	}

	if !isTeamMember {
		return fmt.Errorf("[Security Error] access denied: you do not belong to team '%s'", teamName)
	}

    // ==========================================
	// DYNAMIC VERSIONING LOGIC
	// ==========================================
	// Query for the highest existing version of this file name within this specific team
	versionQuery := fmt.Sprintf("team_id=eq.%s&name=eq.%s&order=version.desc&limit=1", teamID, safeName)
	vResp, err := s.MakeDBRequest("GET", "safe?"+versionQuery, nil, nil)
	if err != nil {
		return fmt.Errorf("[Database Error] failed to check file version history: %v", err)
	}
	defer vResp.Body.Close()

	vBodyBytes, _ := io.ReadAll(vResp.Body)
	
	var existingSafes []struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(vBodyBytes, &existingSafes); err != nil {
		return fmt.Errorf("[Database Error] failed to decode version history: %v", err)
	}

	// If it exists, increment by 1. Otherwise, default to version 1.
	nextVersion := 1
	if len(existingSafes) > 0 {
		nextVersion = existingSafes[0].Version + 1
	}
	// ==========================================

    // 2. Encryption logic: Read file -> Generate Team Key -> AES-GCM Encrypt
    plaintext, err := os.ReadFile(filePath)
    if err != nil {
        return fmt.Errorf("[File Error] could not read file: %v", err)
    }

    teamKey := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, teamKey); err != nil {
        return fmt.Errorf("[Crypto Error] failed to generate team key: %v", err)
    }

    encryptedBlob, err := crypto.EncryptAESGCM(plaintext, teamKey)
    if err != nil {
        return fmt.Errorf("[Crypto Error] encryption failed: %v", err)
    }

    // 3. Define the headers map to include the Prefer header
    headers := map[string]string{
        "Prefer": "return=representation",
    }

    // 4. Prepare the payload for the safe table based on your schema
    safeData := map[string]interface{}{
        "team_id": teamID,
        "name":    safeName,
        "lock":    encryptedBlob,
        "version": nextVersion,
    }

    // 5. Make the request with the specific headers
    resp, err := s.MakeDBRequest("POST", "safe?select=id", safeData, headers)
    if err != nil {
        return fmt.Errorf("[Database Error] failed to post safe: %v", err)
    }
    defer resp.Body.Close()
    
    // Read body once into memory to prevent stream exhaustion
    bodyBytes, _ := io.ReadAll(resp.Body)

    if resp.StatusCode >= 400 {
        var apiErr struct {
            Message string `json:"message"`
        }
        json.Unmarshal(bodyBytes, &apiErr)
        return fmt.Errorf("[Database Error] %s", apiErr.Message)
    }

    // Decode the array response from bodyBytes using json.Unmarshal
    var safeRes []struct {
        ID string `json:"id"`
    }

    if err := json.Unmarshal(bodyBytes, &safeRes); err != nil {
        return fmt.Errorf("[Database Error] failed to decode safe response: %v", err)
    }

    if len(safeRes) == 0 {
        return fmt.Errorf("[Database Error] safe id not returned")
    }
    safeID := safeRes[0].ID

    // 6. Wrap Keys into Envelopes
    var envelopes []map[string]interface{}
    for _, member := range members {
        if all || slices.Contains(usernames, member.Username) {
            
            // 1. Decode 32-byte public key from Base64
            recipientKeyBytes, err := base64.StdEncoding.DecodeString(member.PublicKey)
            if err != nil || len(recipientKeyBytes) != 32 {
                fmt.Printf("[Key Error] skipping %s: invalid 25519 public key\n", member.Username)
                continue
            }
            
            var recipientPubKey [32]byte
            copy(recipientPubKey[:], recipientKeyBytes)

            // 2. Encrypt the teamKey using NaCl Box (Anonymous Sender mode)
            // This generates a one-time ephemeral key internally to protect the payload
            encryptedTeamKey, err := box.SealAnonymous(nil, teamKey, &recipientPubKey, rand.Reader)
            if err != nil {
                fmt.Printf("[Crypto Error] failed to wrap key for %s: %v\n", member.Username, err)
                continue
            }

            // 3. Append to envelopes as Base64 string
            envelopes = append(envelopes, map[string]interface{}{
                "safe_id":             safeID,
                "user_id":             member.ID,
                "encrypted_team_key": base64.StdEncoding.EncodeToString(encryptedTeamKey),
            })
        }
    }


    // 7. Final Step: Batch Insert Envelopes
    if len(envelopes) == 0 {
        return fmt.Errorf("[Validation Error] no recipients selected for safe distribution")
    }

    _, err = s.MakeDBRequest("POST", "envelopes", envelopes, nil)
    if err != nil {
        return fmt.Errorf("[Database Error] failed to distribute keys: %v", err)
    }

    fmt.Printf("✅ Safe '%s' successfully distributed within team '%s'.\n", safeName, teamName)
    return nil
}


// GetSafe retrieves an encrypted safe file, pulls the user's envelope, prompts for passphrase, and decrypts the payload.
func (s *SupabaseClient) GetSafe(userID uuid.UUID, teamName string, safeName string, version int) ([]byte, error) {
	// 1. Fetch team members to cross-validate team existence and sender identity
	members, teamID, err := s.FetchTeamMembersWithPublicKeys(teamName)
	if err != nil {
		return nil, err
	}

	// Verify the operator actually belongs to this team context
	var currentUser struct {
		PublicKey string
	}
	isMember := false
	for _, m := range members {
		if m.ID == userID.String() {
			isMember = true
			currentUser.PublicKey = m.PublicKey
			break
		}
	}
	if !isMember {
		return nil, fmt.Errorf("[Security Error] access denied: you do not belong to team '%s'", teamName)
	}

	// 2. Locate the requested safe record (Latest version vs Specified version)
	var safeQuery string
	if version > 0 {
		safeQuery = fmt.Sprintf("team_id=eq.%s&name=eq.%s&version=eq.%d&limit=1", teamID, safeName, version)
	} else {
		safeQuery = fmt.Sprintf("team_id=eq.%s&name=eq.%s&order=version.desc&limit=1", teamID, safeName)
	}

	resp, err := s.MakeDBRequest("GET", "safe?"+safeQuery, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("[Database Error] failed to retrieve safe record: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var safes []struct {
		ID      string `json:"id"`
		Lock    string `json:"lock"` // The main AES-GCM encrypted payload blob
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(bodyBytes, &safes); err != nil || len(safes) == 0 {
		return nil, fmt.Errorf("[Database Error] safe target '%s' not found for this team context", safeName)
	}
	targetSafe := safes[0]

	// 3. Extract the encrypted distribution envelope containing the encrypted team key for this specific user
	envelopeQuery := fmt.Sprintf("safe_id=eq.%s&user_id=eq.%s&limit=1", targetSafe.ID, userID)
	envResp, err := s.MakeDBRequest("GET", "envelopes?"+envelopeQuery, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("[Database Error] failed to retrieve access envelope: %v", err)
	}
	defer envResp.Body.Close()

	envBodyBytes, _ := io.ReadAll(envResp.Body)
	var envelopes []struct {
		EncryptedTeamKey string `json:"encrypted_team_key"`
	}
	if err := json.Unmarshal(envBodyBytes, &envelopes); err != nil || len(envelopes) == 0 {
		return nil, fmt.Errorf("[Security Error] you do not have an access envelope distributed for this safe version")
	}
	targetEnvelope := envelopes[0]

	// 4. Pull the user's encrypted private key straight out of the users table profile record
	userResp, err := s.MakeDBRequest("GET", fmt.Sprintf("users?id=eq.%s&limit=1", userID), nil, nil)
	if err != nil {
		return nil, fmt.Errorf("[Database Error] failed to retrieve user keys: %v", err)
	}
	defer userResp.Body.Close()

	userBodyBytes, _ := io.ReadAll(userResp.Body)
	var users []struct {
		EncryptedPrivateKey string `json:"encrypted_private_key"`
	}
	if err := json.Unmarshal(userBodyBytes, &users); err != nil || len(users) == 0 {
		return nil, fmt.Errorf("[Database Error] local user metadata profile record missing")
	}

	// 5. Prompt securely in terminal loop for passphrase to unlock their master private key
	fmt.Print("🔑 Enter your master passphrase to unlock safe: ")
	passphraseBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Inject trailing newline to reset terminal alignment
	if err != nil {
		return nil, fmt.Errorf("[Terminal Error] failed to capture passkey input stream: %v", err)
	}

	// 6. Decrypt user's local master private key on the fly using passphrase
	// (Assumes crypto.DecryptPrivateKeyWithPassphrase implements your local storage key derivation wrapper)
	decryptedPrivateKeyBytes, err := crypto.DecryptPrivateKeyWithPassphrase(users[0].EncryptedPrivateKey, passphraseBytes)
	if err != nil {
		return nil, fmt.Errorf("[Crypto Error] verification failed: invalid passphrase provided")
	}

	var userPrivKey [32]byte
	copy(userPrivKey[:], decryptedPrivateKeyBytes)

	// 7. Unwrap the underlying symmetric Team Key using Curve25519/X25519 Anonymous Box open
	wrappedKeyBytes, err := base64.StdEncoding.DecodeString(targetEnvelope.EncryptedTeamKey)
	if err != nil {
		return nil, fmt.Errorf("[Crypto Error] malformed distribution envelope payload")
	}

	teamKey, ok := box.OpenAnonymous(nil, wrappedKeyBytes, nil, &userPrivKey)
	if !ok {
		return nil, fmt.Errorf("[Crypto Error] asymmetric box opening failed: key alignment corrupt")
	}

	// 8. Decrypt the raw source variable payload file contents via AES-GCM using decoded teamKey
	encryptedFileBytes, err := base64.StdEncoding.DecodeString(targetSafe.Lock)
	if err != nil {
		return nil, fmt.Errorf("[Crypto Error] malformed encrypted safe lock payload data stream")
	}

	// (Assumes crypto.DecryptAESGCM or inline standard library block parsing)
	plaintext, err := crypto.DecryptAESGCM(encryptedFileBytes, teamKey)
	if err != nil {
		return nil, fmt.Errorf("[Crypto Error] symmetrical safe lock decryption cycle failure: %v", err)
	}

	fmt.Printf("✅ Successfully decrypted '%s' (Version %d)\n", safeName, targetSafe.Version)
	return plaintext, nil
}