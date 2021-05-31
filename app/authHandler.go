package app

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ganganikalpana/BethelDashBoard/dto"
	"github.com/ganganikalpana/BethelDashBoard/logger"
	"github.com/ganganikalpana/BethelDashBoard/service"
	"github.com/gorilla/mux"
)

type AuthHandler struct {
	service service.AuthService
}

func (a AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var RegisterRequest dto.RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&RegisterRequest)
	if err != nil {
		logger.Error("error while decoding register request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := a.service.Register(RegisterRequest)
		if appErr != nil {

			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, token)
		}
	}

}
func (a AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var LoginRequest dto.LoginRequest
	err := json.NewDecoder(r.Body).Decode(&LoginRequest)
	if err != nil {
		logger.Error("error while decoding login request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := a.service.Login(LoginRequest)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}

}
func (a AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var code *dto.EmailVericationRequest
	err := json.NewDecoder(r.Body).Decode(&code)
	if err != nil {
		logger.Error("error while decoding email verify request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		appErr := a.service.VerifyE(code)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())

		} else {
			writeResponse(w, http.StatusOK, authorizedResponse("email verified"))
		}
	}

}
func (a AuthHandler) VerifyMobile(w http.ResponseWriter, r *http.Request) {
	var code *dto.EmailVericationRequest
	err := json.NewDecoder(r.Body).Decode(&code)
	if err != nil {
		logger.Error("error while decoding email verify request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		appErr := a.service.VerifyM(code)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())

		} else {
			writeResponse(w, http.StatusOK, authorizedResponse("mobile number verified"))
		}
	}

}
func (a AuthHandler) ForgetPassword(w http.ResponseWriter, r *http.Request) {
	var email *dto.ForgetPasswordRequest
	err := json.NewDecoder(r.Body).Decode(&email)
	if err != nil {
		logger.Error("error while decoding forgot password request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		appErr := a.service.ForgotPw(email)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())

		} else {
			writeResponse(w, http.StatusOK, authorizedResponse("email sent...."))
		}
	}

}
func (a AuthHandler) ForgotpwEmailver(w http.ResponseWriter, r *http.Request) {
	var forgotPwEmailVer *dto.ForgetPwEmailVerRequest
	err := json.NewDecoder(r.Body).Decode(&forgotPwEmailVer)
	vars := mux.Vars(r)
	forgotPwEmailVer.EmailEnc = vars["emailEnc"]
	forgotPwEmailVer.EmailVerPassword = vars["hash"]
	if err != nil {
		logger.Error("error while decoding forgot password request" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		appErr := a.service.ForgotPwEmailVer(forgotPwEmailVer)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())

		} else {
			writeResponse(w, http.StatusOK, authorizedResponse("password reset successfully"))
		}
	}

}

func (a AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var refreshRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		logger.Error("Error while decoding refresh token request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := a.service.Refresh(refreshRequest)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}

}

func (a AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)
	fmt.Println("1")

	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		fmt.Println("2")
		appErr := a.service.Verify(urlParams)
		if appErr != nil {
			writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse("verified"))
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}

}
func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}
func authorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": true,
		"message":      msg,
	}

}
func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
