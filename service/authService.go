package service

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/ganganikalpana/BethelDashBoard/domain"
	"github.com/ganganikalpana/BethelDashBoard/dto"
	"github.com/ganganikalpana/BethelDashBoard/email"
	"github.com/ganganikalpana/BethelDashBoard/errs"
	"github.com/ganganikalpana/BethelDashBoard/logger"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
	Refresh(request dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
	Register(request dto.RegisterRequest) (*domain.User, *errs.AppError)
	VerifyE(code *dto.EmailVericationRequest) *errs.AppError
	VerifyM(code *dto.EmailVericationRequest) *errs.AppError
	ForgotPw(email *dto.ForgetPasswordRequest) *errs.AppError
	ForgotPwEmailVer(e *dto.ForgetPwEmailVerRequest) *errs.AppError
}

type DefaultAuthService struct {
	repo            domain.AuthRepository
	rolePermissions domain.RolePermissions
}

func (d DefaultAuthService) Register(request dto.RegisterRequest) (*domain.User, *errs.AppError) {
	newUser := domain.User{
		Email:    request.Email,
		Password: request.Password,
		Role:     request.Role,
		Profile: domain.Profile{
			Fname:         request.Fname,
			Lname:         request.Lname,
			AddressNo:     request.AddressNo,
			Address_Line1: request.Address_Line1,
			Address_Line2: request.Address_Line2,
			PhoneNo:       request.PhoneNo,
			Country:       request.Country,
		},
	}
	p, err := d.repo.Insert(newUser)
	if err != nil {
		return nil, err
	}
	return p, nil
}
func (d DefaultAuthService) Login(request dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var appErr *errs.AppError
	var login *domain.Login
	login, appErr = d.repo.FindBy(request.Email, request.Password)
	if appErr != nil {
		return nil, appErr
	}
	claims := login.ClaimsForAccessToken()
	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string
	accessToken, appErr = authToken.NewAccessToken()
	if appErr != nil {
		return nil, appErr
	}
	refreshToken, appErr = d.repo.GenerateAndSaveRefreshTokenToStore(authToken)
	if appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}
func (d DefaultAuthService) ForgotPw(e *dto.ForgetPasswordRequest) *errs.AppError {
	var appErr *errs.AppError
	var email string
	email = e.Email
	appErr = d.repo.FindbyForgetPwEmail(email)
	if appErr != nil {
		return appErr
	}
	return nil

}
func (d DefaultAuthService) ForgotPwEmailVer(e *dto.ForgetPwEmailVerRequest) *errs.AppError {
	var appErr *errs.AppError
	appErr = d.repo.ForgotPwEmailVer(e.Email,e.EmailEnc, e.EmailVerPassword, e.ConfirmPw, e.Password)
	if appErr != nil {
		return appErr
	}
	return nil

}

func (s DefaultAuthService) Refresh(req dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	vErr := req.IsAccessTokenValid()
	if vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			var appErr *errs.AppError
			appErr = s.repo.RefreshTokenExists(req.RefreshToken)
			if appErr != nil {
				return nil, appErr
			}
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(req.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("invalid token")
	}
	return nil, errs.NewAuthenticationError("cannot generate a new access token until the current one expires")

}

func (s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {

	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		if jwtToken.Valid {
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errs.NewAuthorizationError("request not verified with the token claims")
				}
			}
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("Invalid token")
		}
	}
}
func (s DefaultAuthService) VerifyE(code *dto.EmailVericationRequest) *errs.AppError {

	fmt.Println(code.VCode)
	c := email.EmailVerication{
		Email: code.Email,
		VCode: code.VCode,
	}
	return s.repo.FindByEmail(&c)
}
func (s DefaultAuthService) VerifyM(code *dto.EmailVericationRequest) *errs.AppError {

	fmt.Println(code.VCode)
	c := email.EmailVerication{
		Email: code.Email,
		VCode: code.VCode,
	}
	return s.repo.FindCodeM(&c)
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {

	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {

		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})

	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}

	return token, nil
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{repo, permissions}

}
