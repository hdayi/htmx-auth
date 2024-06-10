package services

import (
	"htmx-jwt/dto"
)

// veritabani olmadigindan boyle birsey
func GetUsers() []*dto.UserDto {
	// Encrypt'ing password
	// password, _:=bcrypt.GenerateFromPassword([]byte("alican"), 8)
	return []*dto.UserDto{
		{
			ID:       "1",
			Username: "ae",
			Password: "alican",
		},
		{
			ID:       "2",
			Username: "hd",
			Password: "hacican",
		},
	}
}
