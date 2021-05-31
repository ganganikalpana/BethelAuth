package domain

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/mgo.v2/bson"
)

const HMAC_SAMPLE_SECRET = "hmacSampleSecret"
const ACCESS_TOKEN_DURATION = time.Hour
const REFRESH_TOKEN_DURATION = time.Hour * 24 * 30

type RefreshTokenClaims struct {
	TokenType string `json:"token_type"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	jwt.StandardClaims
}
type AccessTokenClaims struct {
	UserId bson.ObjectId `json:"userId"`
	Email  string        `json:"email"`
	Role   string        `json:"role"`
	// EmailVerify  bool   `json:"emailverify"`
	// MobileVerify bool   `json:"mobileverify"`
	// Activate     bool   `json:"activate"`
	jwt.StandardClaims
}

func (c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}
func (c AccessTokenClaims) IsValidId(userId bson.ObjectId) bool {
	return c.UserId == userId
}
func (c AccessTokenClaims) RefreshTokenclaims() RefreshTokenClaims {
	return RefreshTokenClaims{
		TokenType: "refresh_token",
		Email:     c.Email,
		Role:      c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(REFRESH_TOKEN_DURATION).Unix(),
		},
	}
}
func (c RefreshTokenClaims) AccessTokenClaims() AccessTokenClaims {
	return AccessTokenClaims{
		Email: c.Email,
		Role:  c.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
func (c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	// if !c.IsValidId(urlParams["email"]) {
	// 	return true //changed to true.................................................................................i have no idea
	// }
	return true

}
