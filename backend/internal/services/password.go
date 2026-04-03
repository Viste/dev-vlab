package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func CheckPasswordHash(password, hash string) bool {
	parts := strings.SplitN(hash, "$", 3)
	if len(parts) != 3 {
		return false
	}

	method := parts[0]
	salt := parts[1]
	expected := parts[2]

	methodParts := strings.Split(method, ":")
	if len(methodParts) != 3 || methodParts[0] != "pbkdf2" || methodParts[1] != "sha256" {
		return false
	}

	iterations, err := strconv.Atoi(methodParts[2])
	if err != nil {
		return false
	}

	dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	computed := hex.EncodeToString(dk)

	return hmac.Equal([]byte(computed), []byte(expected))
}

func HashPassword(password string) string {
	salt := generateRandomString(16)
	iterations := 600000
	dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	hash := hex.EncodeToString(dk)
	return fmt.Sprintf("pbkdf2:sha256:%d$%s$%s", iterations, salt, hash)
}
