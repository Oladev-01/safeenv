//go:build ignore
package main

import (
	"fmt"
	"github.com/Oladev-01/safeenv/internal/crypto"
)

func main() {
	// 1. Paste the exact string from your Supabase table here
	encryptedStringFromDB := "NF3HdF6ts0CO1Q4u8feHfIA3uaSE8muqZDE9tjC1DCuquLeV6L2sCDzh4/Ml3egIRLKTy5h2LVhIrs2Q"
	
	// 2. Define the exact passwords you want to test against
	testPassword := []byte("Mojibola@0534")
	salt := "dfPpFkWdz2/9axY9DVenIw=="

	fmt.Println("Testing decryption algorithm manually...")
	
	// Run the function directly
	decryptedBytes, err := crypto.DecryptPrivateKeyWithPassphrase(encryptedStringFromDB, salt, testPassword)
	if err != nil {
		fmt.Printf("❌ Decryption Failed: %v\n", err)
		return
	}

	fmt.Printf("✅ Decryption Success! Raw Private Key (Hex): %x\n", decryptedBytes)
}