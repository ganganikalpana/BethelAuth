package utils

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

func Check(content, encrypted string) bool {
	return strings.EqualFold(Encode(content), encrypted)
}
func Encode(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// import (
// 	"crypto/aes"
// 	"crypto/cipher"
// 	"crypto/rand"
// 	"errors"
// 	"io"
// )

// func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
// 	c, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	gcm, err := cipher.NewGCM(c)
// 	if err != nil {
// 		return nil, err
// 	}

// 	nonce := make([]byte, gcm.NonceSize())
// 	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
// 		return nil, err
// 	}

// 	return gcm.Seal(nonce, nonce, plaintext, nil), nil
// }

// func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
// 	c, err := aes.NewCipher(key)
// 	if err != nil {
// 		return nil, err
// 	}

// 	gcm, err := cipher.NewGCM(c)
// 	if err != nil {
// 		return nil, err
// 	}

// 	nonceSize := gcm.NonceSize()
// 	if len(ciphertext) < nonceSize {
// 		return nil, errors.New("ciphertext too short")
// 	}

// 	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
// 	return gcm.Open(nil, nonce, ciphertext, nil)
// }
