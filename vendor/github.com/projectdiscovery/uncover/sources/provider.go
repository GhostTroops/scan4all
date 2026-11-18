package sources

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	"github.com/projectdiscovery/utils/generic"
)

var (
	UncoverConfigDir = folderutil.AppConfigDirOrDefault(".uncover-config", "uncover")
	// DefaultProviderConfigLocation where keys and config of providers are stored
	DefaultProviderConfigLocation = filepath.Join(UncoverConfigDir, "provider-config.yaml")
)

type Provider struct {
	Shodan     []string `yaml:"shodan"`
	Censys     []string `yaml:"censys"`
	Fofa       []string `yaml:"fofa"`
	Quake      []string `yaml:"quake"`
	Hunter     []string `yaml:"hunter"`
	ZoomEye    []string `yaml:"zoomeye"`
	Netlas     []string `yaml:"netlas"`
	CriminalIP []string `yaml:"criminalip"`
	Publicwww  []string `yaml:"publicwww"`
	HunterHow  []string `yaml:"hunterhow"`
	Google     []string `yaml:"google"`
	Odin       []string `yaml:"odin"`
	BinaryEdge []string `yaml:"binaryedge"`
	Onyphe     []string `yaml:"onyphe"`
	Driftnet   []string `yaml:"driftnet"`
	GreyNoise  []string `yaml:"greynoise"`
	Daydaymap  []string `yaml:"daydaymap"`
	NerdyData  []string `yaml:"nerdydata"`
}

// NewProvider loads provider keys from default location and env variables
func NewProvider() *Provider {
	p := &Provider{}
	if err := p.LoadProviderConfig(DefaultProviderConfigLocation); err != nil {
		gologger.Error().Msgf("failed to load provider keys got %v", err)
	}
	p.LoadProviderKeysFromEnv()
	return p
}

func (provider *Provider) GetKeys() Keys {
	keys := Keys{}

	if len(provider.Censys) > 0 {
		censysKeys := provider.Censys[rand.Intn(len(provider.Censys))]
		parts := strings.Split(censysKeys, ":")
		if len(parts) == 2 {
			keys.CensysToken = parts[0]
			keys.CensysOrgId = parts[1]
		}
	}

	if len(provider.Shodan) > 0 {
		keys.Shodan = provider.Shodan[rand.Intn(len(provider.Shodan))]
	}

	if len(provider.Fofa) > 0 {
		fofaKeys := provider.Fofa[rand.Intn(len(provider.Fofa))]
		parts := strings.Split(fofaKeys, ":")
		if len(parts) == 2 {
			keys.FofaEmail = parts[0]
			keys.FofaKey = parts[1]
		}
	}

	if len(provider.Quake) > 0 {
		keys.QuakeToken = provider.Quake[rand.Intn(len(provider.Quake))]
	}

	if len(provider.Hunter) > 0 {
		keys.HunterToken = provider.Hunter[rand.Intn(len(provider.Hunter))]
	}

	if len(provider.ZoomEye) > 0 {
		keys.ZoomEyeToken = provider.ZoomEye[rand.Intn(len(provider.ZoomEye))]
	}

	if len(provider.Netlas) > 0 {
		keys.NetlasToken = provider.Netlas[rand.Intn(len(provider.Netlas))]
	}

	if len(provider.CriminalIP) > 0 {
		keys.CriminalIPToken = provider.CriminalIP[rand.Intn(len(provider.CriminalIP))]
	}

	if len(provider.Publicwww) > 0 {
		keys.PublicwwwToken = provider.Publicwww[rand.Intn(len(provider.Publicwww))]
	}
	if len(provider.HunterHow) > 0 {
		keys.HunterHowToken = provider.HunterHow[rand.Intn(len(provider.HunterHow))]
	}
	if len(provider.Google) > 0 {
		googleKeys := provider.Google[rand.Intn(len(provider.Google))]
		parts := strings.Split(googleKeys, ":")
		if len(parts) == 2 {
			keys.GoogleKey = parts[0]
			keys.GoogleCX = parts[1]
		}
	}
	if len(provider.Odin) > 0 {
		keys.OdinToken = provider.Odin[rand.Intn(len(provider.Odin))]
	}
	if len(provider.BinaryEdge) > 0 {
		keys.BinaryEdgeToken = provider.BinaryEdge[rand.Intn(len(provider.BinaryEdge))]
	}
	if len(provider.Onyphe) > 0 {
		keys.OnypheKey = provider.Onyphe[rand.Intn(len(provider.Onyphe))]
	}
	if len(provider.Driftnet) > 0 {
		keys.DriftnetToken = provider.Driftnet[rand.Intn(len(provider.Driftnet))]
	}
	if len(provider.GreyNoise) > 0 {
		keys.GreyNoiseKey = provider.GreyNoise[rand.Intn(len(provider.GreyNoise))]
	}
	if len(provider.Daydaymap) > 0 {
		keys.Daydaymap = provider.Daydaymap[rand.Intn(len(provider.Daydaymap))]
	}
	if len(provider.NerdyData) > 0 {
		keys.NerdyDataToken = provider.NerdyData[rand.Intn(len(provider.NerdyData))]
	}

	return keys
}

// LoadProvidersFrom loads provider config from given location
func (provider *Provider) LoadProviderConfig(location string) error {
	if !fileutil.FileExists(location) {
		//create provider config file if it doesn't exist
		if err := fileutil.Marshal(fileutil.YAML, []byte(location), Provider{}); err != nil {
			return errorutil.NewWithTag("uncover", "couldn't write provider config file(%s): %s\n", location, err)
		}
	}
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), provider)
}

// LoadProviderKeysFromEnv loads provider keys from env variables
func (provider *Provider) LoadProviderKeysFromEnv() {
	appendIfExists := func(arr []string, envName string) []string {
		if value, ok := os.LookupEnv(envName); ok {
			return append(arr, value)
		}
		return arr
	}
	provider.Shodan = appendIfExists(provider.Shodan, "SHODAN_API_KEY")
	provider.Hunter = appendIfExists(provider.Hunter, "HUNTER_API_KEY")
	provider.Quake = appendIfExists(provider.Quake, "QUAKE_TOKEN")
	provider.Netlas = appendIfExists(provider.Netlas, "NETLAS_API_KEY")
	provider.CriminalIP = appendIfExists(provider.CriminalIP, "CRIMINALIP_API_KEY")
	provider.Publicwww = appendIfExists(provider.Publicwww, "PUBLICWWW_API_KEY")
	provider.HunterHow = appendIfExists(provider.HunterHow, "HUNTERHOW_API_KEY")
	provider.ZoomEye = appendIfExists(provider.ZoomEye, "ZOOMEYE_API_KEY")
	provider.Driftnet = appendIfExists(provider.Driftnet, "DRIFTNET_API_KEY")
	provider.Daydaymap = appendIfExists(provider.Daydaymap, "DAYDAYMAP_API_KEY")

	appendIfAllExists := func(arr []string, env1 string, env2 string) []string {
		if val1, ok := os.LookupEnv(env1); ok {
			if val2, ok2 := os.LookupEnv(env2); ok2 {
				return append(arr, fmt.Sprintf("%s:%s", val1, val2))
			} else {
				gologger.Error().Msgf("%v env variable exists but %v does not", env1, env2)
			}
		}
		return arr
	}
	provider.Fofa = appendIfAllExists(provider.Fofa, "FOFA_EMAIL", "FOFA_KEY")
	provider.Censys = appendIfAllExists(provider.Censys, "CENSYS_API_TOKEN", "CENSYS_ORGANIZATION_ID")
	provider.Google = appendIfAllExists(provider.Google, "GOOGLE_API_KEY", "GOOGLE_API_CX")
	provider.Odin = appendIfExists(provider.Odin, "ODIN_API_KEY")
	provider.BinaryEdge = appendIfExists(provider.BinaryEdge, "BINARYEDGE_API_KEY")
	provider.Onyphe = appendIfExists(provider.Onyphe, "ONYPHE_API_KEY")
	provider.GreyNoise = appendIfExists(provider.GreyNoise, "GREYNOISE_API_KEY")
	provider.NerdyData = appendIfExists(provider.NerdyData, "NERDYDATA_API_KEY")
}

// HasKeys returns true if at least one agent/source has keys
func (provider *Provider) HasKeys() bool {
	return generic.EqualsAny(true,
		len(provider.Censys) > 0,
		len(provider.Shodan) > 0,
		len(provider.Fofa) > 0,
		len(provider.Quake) > 0,
		len(provider.Hunter) > 0,
		len(provider.ZoomEye) > 0,
		len(provider.Netlas) > 0,
		len(provider.CriminalIP) > 0,
		len(provider.HunterHow) > 0,
		len(provider.Google) > 0,
		len(provider.Publicwww) > 0,
		len(provider.Odin) > 0,
		len(provider.BinaryEdge) > 0,
		len(provider.Onyphe) > 0,
		len(provider.Driftnet) > 0,
		len(provider.GreyNoise) > 0,
		len(provider.Daydaymap) > 0,
		len(provider.NerdyData) > 0,
	)
}

func init() {
	// check if config dir exists
	if !fileutil.FolderExists(UncoverConfigDir) {
		if err := fileutil.CreateFolder(UncoverConfigDir); err != nil {
			gologger.Warning().Msgf("couldn't create uncover config dir: %s\n", err)
		}
	}
	// create default provider file if it doesn't exist
	if !fileutil.FileExists(DefaultProviderConfigLocation) {
		if err := fileutil.Marshal(fileutil.YAML, []byte(DefaultProviderConfigLocation), Provider{}); err != nil {
			gologger.Warning().Msgf("couldn't write provider default file: %s\n", err)
		}
	}
}
