package dto

type EmailVericationRequest struct {
	Email string `db:"email" json:"email"`
	VCode string    `db:"verification_code" json:"code"`
}
type ForgetPasswordRequest struct{
	Email string `db:"email"`
}
type ForgetPwEmailVerRequest struct{
	Email string `json:"email"`
	EmailEnc string 
	EmailVerPassword string `json:"hash"`
	Password string `json:"password"`
	ConfirmPw string `json:"confirmpassword"`
}
