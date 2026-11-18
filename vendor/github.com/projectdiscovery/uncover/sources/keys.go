package sources

type Keys struct {
	CensysToken     string
	CensysOrgId     string
	Shodan          string
	FofaEmail       string
	FofaKey         string
	QuakeToken      string
	HunterToken     string
	ZoomEyeToken    string
	NetlasToken     string
	CriminalIPToken string
	PublicwwwToken  string
	HunterHowToken  string
	GoogleKey       string
	GoogleCX        string
	OdinToken       string
	BinaryEdgeToken string
	OnypheKey       string
	DriftnetToken   string
	GreyNoiseKey    string
	Daydaymap       string
	NerdyDataToken  string
}

func (keys Keys) Empty() bool {
	return keys.CensysOrgId == "" &&
		keys.CensysToken == "" &&
		keys.Shodan == "" &&
		keys.FofaEmail == "" &&
		keys.FofaKey == "" &&
		keys.QuakeToken == "" &&
		keys.HunterToken == "" &&
		keys.ZoomEyeToken == "" &&
		keys.NetlasToken == "" &&
		keys.CriminalIPToken == "" &&
		keys.PublicwwwToken == "" &&
		keys.HunterHowToken == "" &&
		keys.GoogleKey == "" &&
		keys.GoogleCX == "" &&
		keys.OdinToken == "" &&
		keys.BinaryEdgeToken == "" &&
		keys.OnypheKey == "" &&
		keys.DriftnetToken == "" &&
		keys.GreyNoiseKey == "" &&
		keys.Daydaymap == "" &&
		keys.NerdyDataToken == ""
}
