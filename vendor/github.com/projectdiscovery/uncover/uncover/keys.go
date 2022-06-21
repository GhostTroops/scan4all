package uncover

type Keys struct {
	CensysToken  string
	CensysSecret string
	Shodan       string
	FofaEmail    string
	FofaKey      string
}

func (keys Keys) Empty() bool {
	return keys.CensysSecret == "" && keys.CensysToken == "" && keys.Shodan == "" && keys.FofaEmail == "" && keys.FofaKey == ""
}
