package domain

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/mgo.v2/bson"
)

type Login struct {
	UserId       bson.ObjectId `bson:"_id" db:"_id"`
	Fname        string        `db:"fname"`
	Lname        string        `db:"lname"`
	Password     string        `db:"password"`
	Email        string        `db:"email"`
	EmailVerify  bool          `db:"emailverify"`
	MobileVerify bool          `db:"mobileverify"`
	Status       bool          `db:"activate"`
	Role         string        `db:"role"`
	Profile      Profile
}

func (l Login) ClaimsForAccessToken() AccessTokenClaims {
	if l.UserId.Valid() {

		return l.claimsForUser()
	} else {
		return l.claimsForAdmin()
	}
}

func (l Login) claimsForUser() AccessTokenClaims {

	return AccessTokenClaims{
		UserId: l.UserId,
		Email:  l.Email,
		Role:   l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
func (l Login) claimsForAdmin() AccessTokenClaims {
	return AccessTokenClaims{
		Email: l.Email,
		Role:  l.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
