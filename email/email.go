package email

import (
	"fmt"
	"net/smtp"
	"time"

	"github.com/ganganikalpana/BethelDashBoard/errs"
)

func EmailVerCode(toEmail string, message []byte) *errs.AppError {
	//sender
	from := "gangani.kalpana19@gmail.com"
	password := "Gangi@1996"
	//reciever
	to := []string{toEmail}
	//smtp
	host := "smtp.gmail.com"
	port := "587"
	address := host + ":" + port
	//message
	// message := []byte(m)
	// athentication data
	auth := smtp.PlainAuth("", from, password, host)
	err := smtp.SendMail(address, auth, from, to, message)
	fmt.Println("go check your gmail")
	fmt.Println(err)
	return nil
}

type EmailVerication struct {
	Email   string    `db:"email" json:"email"`
	VCode   string    `db:"verification_code" json:"code"`
	TimeOut time.Time `db:"timeout"`
}
type ForgetPwEmailVer struct {
	Email        string    `db:"email"`
	HashPasswrod string    `db:"vcode"`
	TimeOut      time.Time `db:"timeout"`
}

func CheckVerificationCode(storedCode int, receivedCode int) *errs.AppError {
	fmt.Println("verCode (from form):", receivedCode)
	if storedCode == receivedCode {
		return nil
	} else {
		return errs.NewNotFoundError("verification failed")
	}
}
func CheckVerificationHash(storedCode string, receivedCode string) *errs.AppError {
	fmt.Println("verCode (from form):", receivedCode)
	if storedCode == receivedCode {
		return nil
	} else {
		return errs.NewNotFoundError("verification failed")
	}
}
