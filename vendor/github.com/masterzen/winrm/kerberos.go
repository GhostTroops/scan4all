package winrm

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/masterzen/winrm/soap"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Settings holds all the information necessary to configure the provider
type Settings struct {
	WinRMUsername        string
	WinRMPassword        string
	WinRMHost            string
	WinRMPort            int
	WinRMProto           string
	WinRMInsecure        bool
	KrbRealm             string
	KrbConfig            string
	KrbSpn               string
	KrbCCache            string
	WinRMUseNTLM         bool
	WinRMPassCredentials bool
}

type ClientKerberos struct {
	clientRequest
	Username  string
	Password  string
	Realm     string
	Hostname  string
	Port      int
	Proto     string
	SPN       string
	KrbConf   string
	KrbCCache string
}

func NewClientKerberos(settings *Settings) *ClientKerberos {
	return &ClientKerberos{
		Username:  settings.WinRMUsername,
		Password:  settings.WinRMPassword,
		Realm:     settings.KrbRealm,
		Hostname:  settings.WinRMHost,
		Port:      settings.WinRMPort,
		Proto:     settings.WinRMProto,
		KrbConf:   settings.KrbConfig,
		KrbCCache: settings.KrbCCache,
		SPN:       settings.KrbSpn,
	}
}

func (c *ClientKerberos) Transport(endpoint *Endpoint) error {
	c.clientRequest.Transport(endpoint)

	return nil
}

func (c *ClientKerberos) Post(clt *Client, request *soap.SoapMessage) (string, error) {
	cfg, err := config.Load(c.KrbConf)
	if err != nil {
		return "", err
	}

	// setup the kerberos client
	var kerberosClient *client.Client
	if len(c.KrbCCache) > 0 {
		b, err := ioutil.ReadFile(c.KrbCCache)
		if err != nil {
			return "", fmt.Errorf("Unable to read ccache file %s: %s\n", c.KrbCCache, err.Error())
		}

		cc := new(credentials.CCache)
		err = cc.Unmarshal(b)
		if err != nil {
			return "", fmt.Errorf("Unable to parse ccache file %s: %s", c.KrbCCache, err.Error())
		}
		kerberosClient, err = client.NewFromCCache(cc, cfg, client.DisablePAFXFAST(true))
		if err != nil {
			return "", fmt.Errorf("Unable to create kerberos client from ccache: %s\n", err.Error())
		}
	} else {
		kerberosClient = client.NewWithPassword(c.Username, c.Realm, c.Password, cfg,
			client.DisablePAFXFAST(true), client.AssumePreAuthentication(true))
	}

	//create an http request
	winrmURL := fmt.Sprintf("%s://%s:%d/wsman", c.Proto, c.Hostname, c.Port)
	winRMRequest, _ := http.NewRequest("POST", winrmURL, strings.NewReader(request.String()))
	winRMRequest.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")

	err = spnego.SetSPNEGOHeader(kerberosClient, winRMRequest, c.SPN)
	if err != nil {
		return "", fmt.Errorf("Unable to set SPNego Header: %s\n", err.Error())
	}

	httpClient := &http.Client{Transport: c.transport}

	resp, err := httpClient.Do(winRMRequest)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var bodyMsg string
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			bodyMsg = fmt.Sprintf("Error retrieving the response's body: %s", err)
		} else {
			bodyMsg = fmt.Sprintf("Response body:\n%s", string(respBody))
		}
		return "", fmt.Errorf("Request returned: %d - %s. %s ", resp.StatusCode, resp.Status, bodyMsg)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}
