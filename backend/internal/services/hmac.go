package services

import (
	"crypto/hmac"
	"crypto/sha256"
)

func hmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
