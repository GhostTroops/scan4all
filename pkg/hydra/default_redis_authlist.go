package hydra

func DefaultRedisList() *AuthList {
	a := NewAuthList()
	a.Username = []string{
		"",
		//"admin",
		//"test",
		//"user",
		//"root",
		//"manager",
		//"webadmin",
	}
	a.Password = []string{
		"redis",
		"123456",
		"zaq1@WSX",
		"qweasdzxc",
		"Passw0rd",
		"password",
		"12345",
		"1234",
		"123",
		"qwerty",
		"1q2w3e4r",
		"1qaz2wsx",
		"qazwsx",
		"123qwe",
		"123qaz",
		"0000",
		"1234567",
		"123456qwerty",
		"password123",
		"12345678",
		"1q2w3e",
		"abc123",
		"test123",
		"123456789",
		"q1w2e3r4",
	}
	a.Special = []Auth{}
	return a
}
