package domain

type Profile struct {
	// UserId  int    `json:"userId" db:"userId"`
	Fname   string `json:"fname" db:"fname"`
	Lname   string `json:"lname"  db:"lname"`
	PhoneNo string `json:"PhoneNo" db:"PhoneNo"`
	// Email         string `json:"email" db:"email"`
	AddressNo     string `json:"addressNo" db:"addressNo"`
	Address_Line1 string `json:"address_line1" db:"address_line1"`
	Address_Line2 string `json:"address_line2" db:"address_line2"`
	Country       string `json:"country" db:"country"`
}
type User struct {
	Email        string
	Password     string `json:"password"`
	Role         string `json:"role" db:"role"`
	Activate     bool   `json:"activate"`
	EmailVerify  bool   `json:"emailverify"`
	MobileVerify bool   `json:"mobileverify"`
	// Token     string `json:"token";sql:"-"`
	Profile Profile
	// ProfileID int
}
