package email

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
)

func GenarateHash(s string) string{
	h := sha1.New()
	h.Write([]byte(s))
	sha1_hash := hex.EncodeToString(h.Sum(nil))
	fmt.Println(s, sha1_hash)
	return sha1_hash
}
