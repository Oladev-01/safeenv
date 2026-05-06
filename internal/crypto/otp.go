package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"golang.org/x/crypto/bcrypt"
)

// GenerateOTP creates a 6-digit numeric string and its bcrypt hash
func GenerateOTP() (string, string, error) {
	// 1. Generate 6 random digits
	otp := ""
	for i := 0; i < 6; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(10))
		otp += fmt.Sprintf("%d", num)
	}

	// 2. Hash it before storing in DB (Zero-Knowledge mindset)
	hashedByte, err := bcrypt.GenerateFromPassword([]byte(otp), 10)
	if err != nil {
		return "", "", err
	}

	return otp, string(hashedByte), nil
}

// VerifyOTP checks the user input against the hashed version from DB
func VerifyOTP(userInput, hashedOTP string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedOTP), []byte(userInput))
	return err == nil
}