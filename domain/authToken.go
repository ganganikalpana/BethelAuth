package domain

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/ganganikalpana/BethelDashBoard/errs"
	"github.com/ganganikalpana/BethelDashBoard/logger"
)

type AuthToken struct {
	token *jwt.Token
}
type RefreshToken struct{
	Token string `db:"refreshToken"`
	DateCreated string `db:"date_created"`
}

func (t AuthToken) NewAccessToken() (string, *errs.AppError) {
	signedSting, err := t.token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("cannot generate access token")
	}
	return signedSting, nil
}
func (t AuthToken) newRefreshToken() (string, *errs.AppError) {
	c := t.token.Claims.(AccessTokenClaims)
	refreshClaims := c.RefreshTokenclaims()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedSting, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("Failed while signing access token: " + err.Error())
		return "", errs.NewUnexpectedError("cannot generate access token")
	}
	return signedSting, nil

}
func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken{token: token}

}
func NewAccessTokenFromRefreshToken(refreshToken string) (string, *errs.AppError) {
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		return "", errs.NewAuthenticationError("invalid or expired refresh token")
	}
	r := token.Claims.(*RefreshTokenClaims)
	accessTokenClaims := r.AccessTokenClaims()
	authToken := NewAuthToken(accessTokenClaims)

	return authToken.NewAccessToken()
}
