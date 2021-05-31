package domain

import (
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	"github.com/ganganikalpana/BethelDashBoard/email"
	"github.com/ganganikalpana/BethelDashBoard/errs"
	"github.com/ganganikalpana/BethelDashBoard/logger"
	"github.com/ganganikalpana/BethelDashBoard/sms"
	"github.com/ganganikalpana/BethelDashBoard/utils"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type AuthRepository interface {
	FindBy(email string, password string) (*Login, *errs.AppError)
	Insert(user User) (*User, *errs.AppError)
	GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError)
	RefreshTokenExists(refreshToken string) *errs.AppError
	FindByEmail(code *email.EmailVerication) *errs.AppError
	FindCodeM(code *email.EmailVerication) *errs.AppError
	FindbyForgetPwEmail(email string) *errs.AppError
	ForgotPwEmailVer(Email, EmailEnc, EmailVerPassword, ConfirmPw, Password string) *errs.AppError
}
type AuthRepositoryDb struct {
	db *mgo.Database
}

func (d AuthRepositoryDb) FindByEmail(code *email.EmailVerication) *errs.AppError {

	e := code.Email
	receivedCode := code.VCode
	col := d.db.C("emailVerification")
	cm := email.EmailVerication{}
	col.Find(bson.M{"email": e}).One(&cm)
	storedCode := cm.VCode
	err := bcrypt.CompareHashAndPassword([]byte(storedCode), []byte(receivedCode))
	if err != nil {
		return errs.NewAuthenticationError("code is not valid")
	} else {
		col = d.db.C("users")
		err := col.Update(bson.M{"email": code.Email}, bson.M{"$set": bson.M{"activate": true}})
		err = col.Update(bson.M{"email": code.Email}, bson.M{"$set": bson.M{"emailverify": true}})
		if err != nil {
			fmt.Println("error while acivate account")
		}
	}
	return nil
}
func (d AuthRepositoryDb) ForgotPwEmailVer(Email, EmailEnc, EmailVerPassword, ConfirmPw, Password string) *errs.AppError {
	if ConfirmPw == Password {
		fmt.Println("")
	} else {
		return errs.NewNotFoundError("password and confirmpassword not same")
	}
	fmt.Println(EmailEnc, Email)
	if !utils.Check(Email, EmailEnc) {
		return errs.NewAuthenticationError("email is wrong")
	}

	col := d.db.C("emailVerification")
	cm := email.EmailVerication{}
	col.Find(bson.M{"email": Email}).One(&cm)
	storedHash := cm.VCode

	err := col.Find(bson.M{"email": Email}).One(&cm)
	if err != nil {
		return errs.NewNotFoundError("email is not registered")
	}
	timeout := cm.TimeOut
	currentTime := time.Now()
	if currentTime.After(timeout) {
		fmt.Println("didn't verify account within 45 minutes")
		return errs.NewNotFoundError("didnt verify within 45 minutes")
	}
	//storedHash := cm.HashPasswrod
	//isValidPassword := ComparePassWord(storedHash, []byte(EmailVerPassword))
	if storedHash != EmailVerPassword {
		fmt.Println("hash is not matching")
		return errs.NewAuthenticationError("hash is not matching")
	}

	var hash []byte
	hash, err = bcrypt.GenerateFromPassword([]byte(Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("error while hashing password")
		return errs.NewAuthenticationError("error hashing")
	}
	col = d.db.C("users")
	err = col.Update(bson.M{"email": Email}, bson.M{"$set": bson.M{"password": hash}})
	if err != nil {
		return errs.NewAuthenticationError("error while updating password")
	}
	fmt.Println("forgotten password has been reset")

	return nil
}

func (d AuthRepositoryDb) FindbyForgetPwEmail(e string) *errs.AppError {
	col := d.db.C("users")
	var cm string
	err := col.Find(bson.M{"email": e}).One(&cm)
	if err != nil {
		if err == mgo.ErrNotFound {
			logger.Error("email is not available")
			return errs.NewNotFoundError("email is not registered")
		}
	}
	now := time.Now()
	timeOut := now.Add(time.Minute * 45)
	rand.Seed(time.Now().UnixNano())
	fmt.Println(cm)

	hash := email.GenarateHash(e)
	col = d.db.C("emailVerification")
	err = col.Update(bson.M{"email": e}, bson.M{"$set": bson.M{"vcode": hash}})
	err = col.Update(bson.M{"email": e}, bson.M{"$set": bson.M{"timeout": timeOut}})
	if err != nil {
		fmt.Println("error while acivate account")
		return nil
	}
	subject := "Subject: MySite Account Recovery\n"
	strTest := e
	strEncrypted := utils.Encode(strTest)
	//fmt.Println(utils.Check(strTest, strEncrypted))
	body := fmt.Sprintf("\nhttp://localhost:8000/auth/resetpassword/%s/%s", hash, strEncrypted)

	message := []byte(subject + body)
	err1 := email.EmailVerCode(e, message)
	if err1 != nil {
		logger.Error("error while sending forget password code")
		return errs.NewNotFoundError("error")
	}
	return nil

}
func (d AuthRepositoryDb) FindCodeM(code *email.EmailVerication) *errs.AppError {
	e := code.Email
	receivedCode := code.VCode
	col := d.db.C("mobileVerification")
	cm := sms.SMSVericationHash{}
	err := col.Find(bson.M{"email": e}).One(&cm)
	if err != nil {
		return errs.NewAuthenticationError("verification code not stored")
	}
	storedCode := cm.VCode
	err = bcrypt.CompareHashAndPassword([]byte(storedCode), []byte(receivedCode))
	if err != nil {
		return errs.NewAuthenticationError("incorrect code!!!")
	} else {
		col = d.db.C("users")
		err := col.Update(bson.M{"email": code.Email}, bson.M{"$set": bson.M{"mobileverify": true}})
		if err != nil {
			fmt.Println("error while acivate account")
		}
	}

	return nil
}

func (d AuthRepositoryDb) Insert(p User) (*User, *errs.AppError) {
	if p.Email == "" {
		return nil, errs.NewUnexpectedError("email is missing")
	}
	if p.Password == "" {
		return nil, errs.NewUnexpectedError("Password is missing")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(p.Password), 10)
	if err != nil {
		return nil, errs.NewUnexpectedError("error while encoding password")
	}

	p.Password = string(hash)

	col := d.db.C("users")
	m := col.Find(bson.M{"email": p.Email})
	n, _ := m.Count()
	if n > 0 {
		logger.Error("email is exist")
		return nil, errs.NewUnexpectedError("email is exist")
	}
	var e email.EmailVerication
	e.Email = p.Email
	code := EmailVerificationCodeGenerate(e)

	subject := "Subject: Our Golang Email\n"
	verCode := strconv.Itoa(code)
	hello := "Verification Code " + verCode
	msg := (subject + hello)
	message := []byte(msg)
	err2 := email.EmailVerCode(e.Email, message)
	if err2 != nil {
		logger.Error("error while sending verification code")
		return nil, errs.NewAuthenticationError("error")
	}
	emailpassword := strconv.Itoa(code)
	hash, err = bcrypt.GenerateFromPassword([]byte(emailpassword), 10)
	e.VCode = string(hash)

	col = d.db.C("emailVerification")
	err1 := col.Insert(e)
	if err1 != nil {
		logger.Error("error while inserting verification code")
		return nil, errs.NewNotFoundError("email verification failed")
	}
	col = d.db.C("users")
	err1 = col.Insert(p)
	if err1 != nil {
		log.Fatal(err1)
	}
	return &p, nil
}

func (d AuthRepositoryDb) FindBy(email1 string, password string) (*Login, *errs.AppError) {
	if email1 == "" {
		return nil, errs.NewUnexpectedError("email is missing")
	}
	if password == "" {
		return nil, errs.NewUnexpectedError("Password is missing")
	}
	col := d.db.C("users")
	cm := Login{}
	err := col.Find(bson.M{"email": email1}).One(&cm)
	if err != nil {
		return nil, errs.NewAuthenticationError("email is not registered")
	}
	if !cm.Status {
		hashedPassword := cm.Password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			return nil, errs.NewAuthenticationError("invalid password")
		}
		isValidPassword := ComparePassWord(hashedPassword, []byte(password))
		if isValidPassword {
			if !cm.MobileVerify {
				col = d.db.C("mobileVerification")
				code := GenerateCode(cm.Profile.PhoneNo)
				s2 := strconv.Itoa(code)
				msg := "Verification Code " + s2
				err = sms.SendSMS(cm.Profile.PhoneNo[1:], msg)
				if err != nil {
					logger.Error("error while sending SMS")
					return nil, errs.NewAuthenticationError("SMS not sent")
				}

				ss := sms.SMSVericationHash{}
				ss.Email = email1
				emailpassword := strconv.Itoa(code)
				hash, err := bcrypt.GenerateFromPassword([]byte(emailpassword), 10)
				ss.VCode = string(hash)
				err = col.Insert(&ss)
				if err != nil {
					logger.Error("error while inserting mobile verification code")
					return nil, errs.NewNotFoundError("mobile verification failed")
				}
			}
			return &cm, nil
		}
	} else {
		return nil, errs.NewAuthenticationError("not an activated account,Please Verify Email....")
	}
	return nil, nil
}
func (d AuthRepositoryDb) GenerateAndSaveRefreshTokenToStore(authToken AuthToken) (string, *errs.AppError) {
	var appErr *errs.AppError
	var refreshToken string
	col := d.db.C("refreshtoken")
	if refreshToken, appErr = authToken.newRefreshToken(); appErr != nil {
		return "", appErr
	}
	r := RefreshToken{
		Token:       refreshToken,
		DateCreated: time.Now().Format("2006-01-02 15:04:05"),
	}
	err := col.Insert(r)
	if err != nil {
		logger.Error("unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("unexpected database error")
	}
	return refreshToken, nil
}
func (d AuthRepositoryDb) RefreshTokenExists(refreshToken string) *errs.AppError {
	col := d.db.C("refreshtoken")
	var cm string
	err := col.Find(bson.M{"token": refreshToken}).One(&cm)

	if err != nil {
		if err == mgo.ErrNotFound {
			return errs.NewAuthenticationError("refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("unexpected database error")
		}
	}
	return nil
}
func ComparePassWord(hashedPassword string, password []byte) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {

		log.Println(err)
		return false
	}
	return true
}
func EmailVerificationCodeGenerate(e email.EmailVerication) (v int) {
	rand.Seed(time.Now().UnixNano())
	rn := rand.Intn(100000)
	fmt.Println("random number:", rn)

	return rn

}
func GenerateCode(m string) int {
	rand.Seed(time.Now().UnixNano())
	rn := rand.Intn(10000)
	return rn
}
func NewAuthRepository(dbClient *mgo.Database) AuthRepositoryDb {
	return AuthRepositoryDb{dbClient}

}
