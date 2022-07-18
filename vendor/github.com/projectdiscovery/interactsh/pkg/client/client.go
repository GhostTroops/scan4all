package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/options"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/interactsh/pkg/settings"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/stringsutil"
	"github.com/rs/xid"
	"gopkg.in/corvus-ch/zbase32.v1"
	"gopkg.in/yaml.v3"
)

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

var authError = errors.New("couldn't authenticate to the server")

// Client is a client for communicating with interactsh server instance.
type Client struct {
	correlationID            string
	secretKey                string
	serverURL                *url.URL
	httpClient               *retryablehttp.Client
	privKey                  *rsa.PrivateKey
	quitChan                 chan struct{}
	disableHTTPFallback      bool
	token                    string
	correlationIdLength      int
	CorrelationIdNonceLength int
}

// Options contains configuration options for interactsh client
type Options struct {
	// ServerURL is the URL for the interactsh server.
	ServerURL string
	// Token if the server requires authentication
	Token string
	// DisableHTTPFallback determines if failed requests over https should not be retried over http
	DisableHTTPFallback bool
	// CorrelationIdLength of the preamble
	CorrelationIdLength int
	// CorrelationIdNonceLengthLength of the nonce
	CorrelationIdNonceLength int
	// HTTPClient use a custom http client
	HTTPClient *retryablehttp.Client
	// SessionInfo to resume an existing session
	SessionInfo *options.SessionInfo
}

// DefaultOptions is the default options for the interact client
var DefaultOptions = &Options{
	ServerURL:                "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
	CorrelationIdLength:      settings.CorrelationIdLengthDefault,
	CorrelationIdNonceLength: settings.CorrelationIdNonceLengthDefault,
}

// New creates a new client instance based on provided options
func New(options *Options) (*Client, error) {
	// if correlation id lengths and nonce are not specified fallback to default:
	if options.CorrelationIdLength == 0 {
		options.CorrelationIdLength = DefaultOptions.CorrelationIdLength
	}
	if options.CorrelationIdNonceLength == 0 {
		options.CorrelationIdNonceLength = DefaultOptions.CorrelationIdNonceLength
	}

	var httpclient *retryablehttp.Client
	if options.HTTPClient != nil {
		httpclient = options.HTTPClient
	} else {
		opts := retryablehttp.DefaultOptionsSingle
		opts.Timeout = 10 * time.Second
		httpclient = retryablehttp.NewClient(opts)
	}

	var correlationID, secretKey, token string

	if options.SessionInfo != nil {
		correlationID = options.SessionInfo.CorrelationID
		secretKey = options.SessionInfo.SecretKey
		token = options.SessionInfo.Token
	} else {
		// Generate a random ksuid which will be used as server secret.
		correlationID = xid.New().String()
		if len(correlationID) > options.CorrelationIdLength {
			correlationID = correlationID[:options.CorrelationIdLength]
		}
		secretKey = uuid.New().String()
		token = options.Token
	}

	client := &Client{
		secretKey:                secretKey,
		correlationID:            correlationID,
		httpClient:               httpclient,
		token:                    token,
		disableHTTPFallback:      options.DisableHTTPFallback,
		correlationIdLength:      options.CorrelationIdLength,
		CorrelationIdNonceLength: options.CorrelationIdNonceLength,
	}
	if options.SessionInfo != nil {
		privKey, err := x509.ParsePKCS1PrivateKey([]byte(options.SessionInfo.PrivateKey))
		if err == nil {
			client.privKey = privKey
		}
		if serverURL, err := url.Parse(options.SessionInfo.ServerURL); err == nil {
			client.serverURL = serverURL
		}
	} else {
		payload, err := client.initializeRSAKeys()
		if err != nil {
			return nil, errors.Wrap(err, "could not initialize rsa keys")
		}

		if err := client.parseServerURLs(options.ServerURL, payload); err != nil {
			return nil, errors.Wrap(err, "could not register to servers")
		}
	}

	return client, nil
}

// initializeRSAKeys does the one-time initialization for RSA crypto mechanism
// and returns the data payload for the client.
func (c *Client) initializeRSAKeys() ([]byte, error) {
	// Generate a 2048-bit private-key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate rsa private key")
	}
	c.privKey = priv
	pub := priv.Public()

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal public key")
	}
	pubkeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	encoded := base64.StdEncoding.EncodeToString(pubkeyPem)
	register := server.RegisterRequest{
		PublicKey:     encoded,
		SecretKey:     c.secretKey,
		CorrelationID: c.correlationID,
	}
	data, err := jsoniter.Marshal(register)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal register request")
	}
	return data, nil
}

// parseServerURLs parses server url string. Multiple URLs are supported
// comma separated and a random one will be used on runtime.
//
// If the https scheme is not working, http is tried. url can be comma separated
// domains or full urls as well.
//
// If the first picked random domain doesn't work, the list of domains is iterated
// after being shuffled.
func (c *Client) parseServerURLs(serverURL string, payload []byte) error {
	if serverURL == "" {
		return errors.New("invalid server url provided")
	}

	values := strings.Split(serverURL, ",")
	firstIdx := mathrand.Intn(len(values))
	gotValue := values[firstIdx]

	registerFunc := func(got string) error {
		if !stringsutil.HasPrefixAny(got, "http://", "https://") {
			got = fmt.Sprintf("https://%s", got)
		}
		parsed, err := url.Parse(got)
		if err != nil {
			return errors.Wrap(err, "could not parse server URL")
		}
	makeReq:
		if err := c.performRegistration(parsed.String(), payload); err != nil {
			if !c.disableHTTPFallback && parsed.Scheme == "https" {
				parsed.Scheme = "http"
				gologger.Verbose().Msgf("Could not register to %s: %s, retrying with http\n", parsed.String(), err)
				goto makeReq
			}
			return err
		}
		c.serverURL = parsed
		return nil
	}
	err := registerFunc(gotValue)
	if err != nil {
		gologger.Verbose().Msgf("Could not register to %s: %s, retrying with remaining\n", gotValue, err)
		values = removeIndex(values, firstIdx)
		mathrand.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })

		for _, value := range values {
			if err = registerFunc(value); err != nil {
				gologger.Verbose().Msgf("Could not register to %s: %s, retrying with remaining\n", gotValue, err)
				continue
			}
			break
		}
	}
	if c.serverURL != nil {
		return nil
	}
	return err // return errors if any.
}

func removeIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

// InteractionCallback is a callback function for a reported interaction
type InteractionCallback func(*server.Interaction)

// StartPolling starts polling the server each duration and returns any events
// that may have been captured by the collaborator server.
func (c *Client) StartPolling(duration time.Duration, callback InteractionCallback) {
	ticker := time.NewTicker(duration)
	c.quitChan = make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				err := c.getInteractions(callback)
				if err != nil && err.Error() == authError.Error() {
					gologger.Fatal().Msgf("Could not authenticate to the server")
				}
			case <-c.quitChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// getInteractions returns the interactions from the server.
func (c *Client) getInteractions(callback InteractionCallback) error {
	builder := &strings.Builder{}
	builder.WriteString(c.serverURL.String())
	builder.WriteString("/poll?id=")
	builder.WriteString(c.correlationID)
	builder.WriteString("&secret=")
	builder.WriteString(c.secretKey)
	req, err := retryablehttp.NewRequest("GET", builder.String(), nil)
	if err != nil {
		return err
	}

	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		if resp.StatusCode == http.StatusUnauthorized {
			return authError
		}
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("could not poll interactions: %s", string(data))
	}
	response := &server.PollResponse{}
	if err := jsoniter.NewDecoder(resp.Body).Decode(response); err != nil {
		gologger.Error().Msgf("Could not decode interactions: %v\n", err)
		return err
	}

	for _, data := range response.Data {
		plaintext, err := c.decryptMessage(response.AESKey, data)
		if err != nil {
			gologger.Error().Msgf("Could not decrypt interaction: %v\n", err)
			continue
		}
		interaction := &server.Interaction{}
		if err := jsoniter.Unmarshal(plaintext, interaction); err != nil {
			gologger.Error().Msgf("Could not unmarshal interaction data interaction: %v\n", err)
			continue
		}
		callback(interaction)
	}

	for _, plaintext := range response.Extra {
		interaction := &server.Interaction{}
		if err := jsoniter.UnmarshalFromString(plaintext, interaction); err != nil {
			gologger.Error().Msgf("Could not unmarshal interaction data interaction: %v\n", err)
			continue
		}
		callback(interaction)
	}

	// handle root-tld data if any
	for _, data := range response.TLDData {
		interaction := &server.Interaction{}
		if err := jsoniter.UnmarshalFromString(data, interaction); err != nil {
			gologger.Error().Msgf("Could not unmarshal interaction data interaction: %v\n", err)
			continue
		}
		callback(interaction)
	}

	return nil
}

// StopPolling stops the polling to the interactsh server.
func (c *Client) StopPolling() {
	close(c.quitChan)
}

// Close closes the collaborator client and deregisters from the
// collaborator server if not explicitly asked by the user.
func (c *Client) Close() error {
	register := server.DeregisterRequest{
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
	}
	data, err := jsoniter.Marshal(register)
	if err != nil {
		return errors.Wrap(err, "could not marshal deregister request")
	}
	URL := c.serverURL.String() + "/deregister"
	req, err := retryablehttp.NewRequest("POST", URL, bytes.NewReader(data))
	if err != nil {
		return errors.Wrap(err, "could not create new request")
	}
	req.ContentLength = int64(len(data))

	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()
	if err != nil {
		return errors.Wrap(err, "could not make deregister request")
	}
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("could not deregister to server: %s", string(data))
	}
	return nil
}

// performRegistration registers the current client with the master server using the
// provided RSA Public Key as well as Correlation Key.
func (c *Client) performRegistration(serverURL string, payload []byte) error {
	// By default we attempt registration once before switching to the next server
	ctx := context.WithValue(context.Background(), retryablehttp.RETRY_MAX, 0)

	URL := serverURL + "/register"
	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", URL, bytes.NewReader(payload))
	if err != nil {
		return errors.Wrap(err, "could not create new request")
	}
	req.ContentLength = int64(len(payload))

	if c.token != "" {
		req.Header.Add("Authorization", c.token)
	}

	resp, err := c.httpClient.Do(req)
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
			_, _ = io.Copy(ioutil.Discard, resp.Body)
		}
	}()
	if err != nil {
		return errors.Wrap(err, "could not make register request")
	}
	if resp.StatusCode == 401 {
		return errors.New("invalid token provided for interactsh server")
	}
	if resp.StatusCode != 200 {
		data, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("could not register to server: %s", string(data))
	}
	response := make(map[string]interface{})
	if jsonErr := jsoniter.NewDecoder(resp.Body).Decode(&response); jsonErr != nil {
		return errors.Wrap(jsonErr, "could not register to server")
	}
	message, ok := response["message"]
	if !ok {
		return errors.New("could not get register response")
	}
	if message.(string) != "registration successful" {
		return fmt.Errorf("could not get register response: %s", message.(string))
	}
	return nil
}

// URL returns a new URL that can be used for external interaction requests.
func (c *Client) URL() string {
	data := make([]byte, c.CorrelationIdNonceLength)
	_, _ = rand.Read(data)
	randomData := zbase32.StdEncoding.EncodeToString(data)
	if len(randomData) > c.CorrelationIdNonceLength {
		randomData = randomData[:c.CorrelationIdNonceLength]
	}

	builder := &strings.Builder{}
	builder.Grow(len(c.correlationID) + len(randomData) + len(c.serverURL.Host) + 1)
	builder.WriteString(c.correlationID)
	builder.WriteString(randomData)
	builder.WriteString(".")
	builder.WriteString(c.serverURL.Host)
	URL := builder.String()
	return URL
}

// decryptMessage decrypts an AES-256-RSA-OAEP encrypted message to string
func (c *Client) decryptMessage(key string, secureMessage string) ([]byte, error) {
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	// Decrypt the key plaintext first
	keyPlaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privKey, decodedKey, nil)
	if err != nil {
		return nil, err
	}

	cipherText, err := base64.StdEncoding.DecodeString(secureMessage)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(keyPlaintext)
	if err != nil {
		return nil, err
	}

	if len(cipherText) < aes.BlockSize {
		return nil, errors.New("ciphertext block size is too small")
	}

	// IV is at the start of the Ciphertext
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// XORKeyStream can work in-place if the two arguments are the same.
	stream := cipher.NewCFBDecrypter(block, iv)
	decoded := make([]byte, len(cipherText))
	stream.XORKeyStream(decoded, cipherText)
	return decoded, nil
}

func (c *Client) SaveSessionTo(filename string) error {
	privateKeyData := x509.MarshalPKCS1PrivateKey(c.privKey)
	sessionInfo := &options.SessionInfo{
		ServerURL:     c.serverURL.String(),
		Token:         c.token,
		PrivateKey:    string(privateKeyData),
		CorrelationID: c.correlationID,
		SecretKey:     c.secretKey,
	}
	data, err := yaml.Marshal(sessionInfo)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, os.ModePerm)
}
