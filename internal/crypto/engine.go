package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
	"github.com/Oladev-01/safeenv/internal/model"
)

// CreateNewIdentity generates a Curve25519 keypair and wraps the private key using Argon2id + AES-GCM
func CreateNewIdentity(passphrase string) (*models.Users, error) {
	// 1. Generate NaCl Box Keypair (Curve25519)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// 2. Generate a random 16-byte salt for Argon2id
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// 3. Derive a 32-byte key from the passphrase
	// Argon2id params: time=1, memory=64MB, threads=4
	masterKey := argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)

	// 4. Encrypt the Private Key using AES-GCM (packs the 12-byte nonce at the front)
	encPriv, err := EncryptAESGCM(priv[:], masterKey)
	if err != nil {
		return nil, err
	}

	return &models.Users{
		PublicKey:     base64.StdEncoding.EncodeToString(pub[:]),
		EncPrivateKey: encPriv,
		Salt:          base64.StdEncoding.EncodeToString(salt),
	}, nil
}

// EncryptAESGCM handles generic symmetric file/key encryption (prepends a 12-byte nonce)
func EncryptAESGCM(plaintext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal attaches the nonce to the beginning of the ciphertext payload string
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptPrivateKeyWithPassphrase pulls the salt from the database column and opens the AES-GCM block
func DecryptPrivateKeyWithPassphrase(encryptedPrivateKeyStr string, saltStr string, passphrase []byte) ([]byte, error) {
	// 1. Decode the user's specific database salt row
	salt, err := base64.StdEncoding.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user profile salt: %v", err)
	}

	// 2. Decode the private key data stream envelope
	encryptedMasterBytes, err := base64.StdEncoding.DecodeString(encryptedPrivateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key base64 data stream: %v", err)
	}

	// 3. Extract the 12-byte nonce prepended by your EncryptAESGCM function
	nonceSize := 12
	if len(encryptedMasterBytes) < nonceSize+16 { // Nonce + min GCM auth tag
		return nil, errors.New("encrypted private key payload stream corrupt or truncated")
	}

	nonce := encryptedMasterBytes[:nonceSize]
	ciphertext := encryptedMasterBytes[nonceSize:]

	// 4. Derive the exact identical key using matching registration parameters (time=1, threads=4)
	derivedKey := argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32)

	// 5. Initialize the standard block decryptor
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 6. Open the envelope and return the raw 32-byte private key bytes
	decryptedKey, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("authentication verification failed: invalid passphrase or data damage detected")
	}

	return decryptedKey, nil
}

// DecryptAESGCM unlocks a raw ciphertext data stream using a verified 32-byte symmetric team access key.
func DecryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	// Check key alignment parameters
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid encryption key layout: must be exactly 32 bytes for AES-256")
	}

	// 1. Initialize the symmetric cipher block engine
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to execute cipher mapping block configuration: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to establish validation wrapper: %v", err)
	}

	// 2. Extract standard 12-byte cryptographic nonce from head of payload stream
	nonceSize := aesGCM.NonceSize() // Safely evaluates to 12 bytes
	if len(ciphertext) < nonceSize {
		return nil, errors.New("target ciphertext payload data corrupted: missing nonce header block")
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	// 3. Process symmetrical payload decryption and execute data authenticity checksum validations
	plaintext, err := aesGCM.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("symmetrical safe lock decryption cycle failure: %v", err)
	}

	return plaintext, nil
}