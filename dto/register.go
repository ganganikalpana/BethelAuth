package dto

type RegisterRequest struct {
	Fname         string `json:"fname" `
	Lname         string `json:"lname"  `
	PhoneNo       string `json:"PhoneNo" `
	Email         string `json:"email" `
	AddressNo     string `json:"addressNo"`
	Address_Line1 string `json:"address_line1" `
	Address_Line2 string `json:"address_line2" `
	Country       string `json:"country" `
	Password      string `json:"password"`
	Role          string `json:"role"`
}
// type RegisterResponse struct {
// 	Fname         string `json:"fname" `
// 	Lname         string `json:"lname"  `
// 	PhoneNo       string `json:"PhoneNo" `
// 	Email         string `json:"email" `
// 	AddressNo     string `json:"addressNo"`
// 	Address_Line1 string `json:"address_line1" `
// 	Address_Line2 string `json:"address_line2" `
// 	Country       string `json:"country" `
// 	Role          string `json:"role"`
// }
