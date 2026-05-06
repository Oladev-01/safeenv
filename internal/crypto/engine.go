package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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
	encPriv, err := encryptAESGCM(priv[:], masterKey)
	if err != nil {
		return nil, err
	}

	return &models.Users{
		PublicKey:           base64.StdEncoding.EncodeToString(pub[:]),
		EncPrivateKey: encPriv,
		Salt:                base64.StdEncoding.EncodeToString(salt),
	}, nil
}

func encryptAESGCM(plaintext []byte, key []byte) (string, error) {
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