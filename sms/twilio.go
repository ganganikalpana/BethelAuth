package sms

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func SendSMS(to, msg string) error {
	secret := "d42c2532100390e782e6e9f24a6004cc"
	key := "AC53194dacefc3b6acab23633abff81362"
	Urlstr := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", key)
	to = "+94703360132"
	msgData := url.Values{}
	msgData.Set("To", to)
	fmt.Println(to)
	msgData.Set("From", "+18582950803")
	msgData.Set("Body", msg)
	fmt.Println(msg)

	msgDataReader := *strings.NewReader(msgData.Encode())
	client := &http.Client{}
	req, _ := http.NewRequest("POST", Urlstr, &msgDataReader)
	req.SetBasicAuth(key, secret)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, _ := client.Do(req)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var data map[string]interface{}
		decoder := json.NewDecoder(resp.Body)
		err := decoder.Decode(&data)
		if err != nil {
			log.Println(err)
			return err
		} else {
			fmt.Println(resp.Status)
		}
	} else {
		log.Println("Error sending SMS!")
		//return *errs.NewUnexpectedError("error...")
		return nil
	}
	return nil
}

type SMSVerication struct {
	Email string `db:"email" json:"email"`
	VCode int    `db:"verification_code" json:"code"`
}
type SMSVericationHash struct {
	Email string `db:"email" json:"email"`
	VCode string `db:"vcode" json:"code"`
}
