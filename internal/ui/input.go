package ui

import (
	"fmt"
	"syscall"
	"unicode"

	"golang.org/x/term"
)

// GetValidatedPassphrase is the single entry point that handles 
// Masked Input, Security Validation, and Confirmation.
func GetValidatedPassphrase() (string, error) {
	for {
		fmt.Print("Enter Master Passphrase: ")
		p1, err := getPassphrase()
		if err != nil {
			return "", err
		}

		// 1. Enforce Security Standards
		if err := validatePwd(p1); err != nil {
			fmt.Printf("❌ %v. Please try again.\n", err)
			continue
		}

		
        fmt.Print("Confirm Master Passphrase: ")
        p2, err := getPassphrase()
        if err != nil {
            return "", err
        }

        if p1 != p2 {
            fmt.Println("❌ Passphrases do not match. Please start over.")
            continue
        }
    

		return p1, nil
	}
}

// getPassphrase handles the raw terminal masking
func getPassphrase() (string, error) {
	bytePass, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println() // Newline after hidden input
	return string(bytePass), nil
}

// validatePwd ensures the password meets SafeEnv standards
func validatePwd(passwd string) error {
	var (
		hasMinLen  = len(passwd) >= 12
		hasNum     bool
		hasSpecial bool
	)

	for _, char := range passwd {
		switch {
		case unicode.IsNumber(char):
			hasNum = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasMinLen {
		return fmt.Errorf("password must be at least 12 characters long")
	}
	if !hasNum {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}