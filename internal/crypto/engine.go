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


// CreateNewIdentity generates a keypair and encrypts the private key using the passphrase
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

	// 4. Encrypt the Private Key using AES-GCM
	encPriv, err := EncryptAESGCM(priv[:], masterKey)
	if err != nil {
		return nil, err
	}

	return &models.Users{
		PublicKey:           base64.StdEncoding.EncodeToString(pub[:]),
		EncPrivateKey: encPriv,
		Salt:                base64.StdEncoding.EncodeToString(salt),
	}, nil
}

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

	// Seal attaches the nonce to the beginning of the ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}


// DecryptPrivateKeyWithPassphrase reconstructs a user's master X25519 private key 
// out of its password-protected storage string format using Argon2id and AES-GCM.
func DecryptPrivateKeyWithPassphrase(encryptedPrivateKeyStr string, passphrase []byte) ([]byte, error) {
	// 1. Decode the composite storage string out of its envelope representation
	encryptedMasterBytes, err := base64.StdEncoding.DecodeString(encryptedPrivateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key base64 data stream: %v", err)
	}

	// 2. Define standard cryptographic extraction slice boundaries
	// Payload layout: [ 16 bytes Salt ] [ 12 bytes Nonce ] [ Encrypted Data Payload... ]
	if len(encryptedMasterBytes) < 16+12+aes.BlockSize {
		return nil, errors.New("encrypted private key payload stream corrupt or truncated")
	}

	salt := encryptedMasterBytes[0:16]
	nonce := encryptedMasterBytes[16:28]
	ciphertext := encryptedMasterBytes[28:]

	// 3. Derive the exact 32-byte symmetrical decryption key using Argon2id
	// These parameters mirror standard secure setup configurations (Memory: 64MB, Iterations: 3, Threads: 2)
	derivedKey := argon2.IDKey(passphrase, salt, 3, 64*1024, 2, 32)

	// 4. Initialize the AES block cipher and open the GCM authentication barrier
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build internal block validation engine: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to mount authentication mode container: %v", err)
	}

	// 5. Unpack cleartext private key contents
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