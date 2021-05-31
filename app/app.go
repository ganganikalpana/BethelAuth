package app

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ganganikalpana/BethelDashBoard/domain"
	"github.com/ganganikalpana/BethelDashBoard/logger"
	"github.com/ganganikalpana/BethelDashBoard/service"
	"github.com/gorilla/mux"
	"gopkg.in/mgo.v2"
)

func SanityCheck() {
	if os.Getenv("SERVER_ADDRESS") == "" {
		log.Fatal("SERVER_ADDRESS is  not defined")
	}
	if os.Getenv("SERVER_PORT") == "" {
		log.Fatal("SERVER_PORT is not defined")
	}
}
func Start() {
	SanityCheck()
	router := mux.NewRouter()

	loginRepository := domain.NewAuthRepository(getDbClient())
	ah := AuthHandler{service.NewLoginService(loginRepository, domain.GetRolePermissions())}

	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodPost)
	router.HandleFunc("/auth/Refresh", ah.Refresh).Methods(http.MethodPost)
	router.HandleFunc("/auth/register", ah.Register).Methods(http.MethodPost)
	router.HandleFunc("/auth/verifyEmail", ah.VerifyEmail).Methods(http.MethodPost)
	router.HandleFunc("/auth/verifyMobile", ah.VerifyMobile).Methods(http.MethodPost)
	router.HandleFunc("/auth/forgetpassword", ah.ForgetPassword).Methods(http.MethodPost)
	 router.HandleFunc("/auth/resetpassword/{emailEnc}/{hash}", ah.ForgotpwEmailver).Methods(http.MethodPost)       // validate email address and send email
	// router.HandleFunc("/forgotpwchange", ah.forgotpwChangeHandler).Methods(http.MethodPost) // renders change pw form and places authInfo in form action
	// router.HandleFunc("/forgotpwemailver", ah.forgotPWverHandler).Methods(http.MethodPost)

	address := os.Getenv("SERVER_ADDRESS")
	port := os.Getenv("SERVER_PORT")
	logger.Info(fmt.Sprintf("Starting OAuth server on %s:%s ...", address, port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router))

}
func getDbClient() *mgo.Database {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	//defer session.Close()
	db := session.DB("Bethel")
	return db
}
