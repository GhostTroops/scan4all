// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// GetCertificate gets a certificate to satisfy clientHello. In getting
// the certificate, it abides the rules and settings defined in the Config
// that matches clientHello.ServerName. It tries to get certificates in
// this order:
//
// 1. Exact match in the in-memory cache
// 2. Wildcard match in the in-memory cache
// 3. Managers (if any)
// 4. Storage (if on-demand is enabled)
// 5. Issuers (if on-demand is enabled)
//
// This method is safe for use as a tls.Config.GetCertificate callback.
func (cfg *Config) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cfg.emit("tls_handshake_started", clientHello)

	// special case: serve up the certificate for a TLS-ALPN ACME challenge
	// (https://tools.ietf.org/html/draft-ietf-acme-tls-alpn-05)
	for _, proto := range clientHello.SupportedProtos {
		if proto == acmez.ACMETLS1Protocol {
			challengeCert, distributed, err := cfg.getTLSALPNChallengeCert(clientHello)
			if err != nil {
				if cfg.Logger != nil {
					cfg.Logger.Error("tls-alpn challenge",
						zap.String("server_name", clientHello.ServerName),
						zap.Error(err))
				}
				return nil, err
			}
			if cfg.Logger != nil {
				cfg.Logger.Info("served key authentication certificate",
					zap.String("server_name", clientHello.ServerName),
					zap.String("challenge", "tls-alpn-01"),
					zap.String("remote", clientHello.Conn.RemoteAddr().String()),
					zap.Bool("distributed", distributed))
			}
			return challengeCert, nil
		}
	}

	// get the certificate and serve it up
	cert, err := cfg.getCertDuringHandshake(clientHello, true, true)
	if err == nil {
		cfg.emit("tls_handshake_completed", clientHello)
	}
	return &cert.Certificate, err
}

// getCertificateFromCache gets a certificate that matches name from the in-memory
// cache, according to the lookup table associated with cfg. The lookup then
// points to a certificate in the Instance certificate cache.
//
// The name is expected to already be normalized (e.g. lowercased).
//
// If there is no exact match for name, it will be checked against names of
// the form '*.example.com' (wildcard certificates) according to RFC 6125.
// If a match is found, matched will be true. If no matches are found, matched
// will be false and a "default" certificate will be returned with defaulted
// set to true. If defaulted is false, then no certificates were available.
//
// The logic in this function is adapted from the Go standard library,
// which is by the Go Authors.
//
// This function is safe for concurrent use.
func (cfg *Config) getCertificateFromCache(hello *tls.ClientHelloInfo) (cert Certificate, matched, defaulted bool) {
	name := normalizedName(hello.ServerName)

	if name == "" {
		// if SNI is empty, prefer matching IP address
		if hello.Conn != nil {
			addr := localIPFromConn(hello.Conn)
			cert, matched = cfg.selectCert(hello, addr)
			if matched {
				return
			}
		}

		// fall back to a "default" certificate, if specified
		if cfg.DefaultServerName != "" {
			normDefault := normalizedName(cfg.DefaultServerName)
			cert, defaulted = cfg.selectCert(hello, normDefault)
			if defaulted {
				return
			}
		}
	} else {
		// if SNI is specified, try an exact match first
		cert, matched = cfg.selectCert(hello, name)
		if matched {
			return
		}

		// try replacing labels in the name with
		// wildcards until we get a match
		labels := strings.Split(name, ".")
		for i := range labels {
			labels[i] = "*"
			candidate := strings.Join(labels, ".")
			cert, matched = cfg.selectCert(hello, candidate)
			if matched {
				return
			}
		}
	}

	// otherwise, we're bingo on ammo; see issues
	// caddyserver/caddy#2035 and caddyserver/caddy#1303 (any
	// change to certificate matching behavior must
	// account for hosts defined where the hostname
	// is empty or a catch-all, like ":443" or
	// "0.0.0.0:443")

	return
}

// selectCert uses hello to select a certificate from the
// cache for name. If cfg.CertSelection is set, it will be
// used to make the decision. Otherwise, the first matching
// unexpired cert is returned. As a special case, if no
// certificates match name and cfg.CertSelection is set,
// then all certificates in the cache will be passed in
// for the cfg.CertSelection to make the final decision.
func (cfg *Config) selectCert(hello *tls.ClientHelloInfo, name string) (Certificate, bool) {
	logger := loggerNamed(cfg.Logger, "handshake")
	choices := cfg.certCache.getAllMatchingCerts(name)
	if len(choices) == 0 {
		if cfg.CertSelection == nil {
			if logger != nil {
				logger.Debug("no matching certificates and no custom selection logic", zap.String("identifier", name))
			}
			return Certificate{}, false
		}
		if logger != nil {
			logger.Debug("no matching certificate; will choose from all certificates", zap.String("identifier", name))
		}
		choices = cfg.certCache.getAllCerts()
	}
	if logger != nil {
		logger.Debug("choosing certificate",
			zap.String("identifier", name),
			zap.Int("num_choices", len(choices)))
	}
	if cfg.CertSelection == nil {
		cert, err := DefaultCertificateSelector(hello, choices)
		if logger != nil {
			logger.Debug("default certificate selection results",
				zap.Error(err),
				zap.String("identifier", name),
				zap.Strings("subjects", cert.Names),
				zap.Bool("managed", cert.managed),
				zap.String("issuer_key", cert.issuerKey),
				zap.String("hash", cert.hash))
		}
		return cert, err == nil
	}
	cert, err := cfg.CertSelection.SelectCertificate(hello, choices)
	if logger != nil {
		logger.Debug("custom certificate selection results",
			zap.Error(err),
			zap.String("identifier", name),
			zap.Strings("subjects", cert.Names),
			zap.Bool("managed", cert.managed),
			zap.String("issuer_key", cert.issuerKey),
			zap.String("hash", cert.hash))
	}
	return cert, err == nil
}

// DefaultCertificateSelector is the default certificate selection logic
// given a choice of certificates. If there is at least one certificate in
// choices, it always returns a certificate without error. It chooses the
// first non-expired certificate that the client supports if possible,
// otherwise it returns an expired certificate that the client supports,
// otherwise it just returns the first certificate in the list of choices.
func DefaultCertificateSelector(hello *tls.ClientHelloInfo, choices []Certificate) (Certificate, error) {
	if len(choices) == 0 {
		return Certificate{}, fmt.Errorf("no certificates available")
	}
	now := time.Now()
	best := choices[0]
	for _, choice := range choices {
		if err := hello.SupportsCertificate(&choice.Certificate); err != nil {
			continue
		}
		best = choice // at least the client supports it...
		if now.After(choice.Leaf.NotBefore) && now.Before(choice.Leaf.NotAfter) {
			return choice, nil // ...and unexpired, great! "Certificate, I choose you!"
		}
	}
	return best, nil // all matching certs are expired or incompatible, oh well
}

// getCertDuringHandshake will get a certificate for hello. It first tries
// the in-memory cache. If no exact certificate for hello is in the cache, the
// config most closely corresponding to hello (like a wildcard) will be loaded.
// If none could be matched from the cache, it invokes the configured certificate
// managers to get a certificate and uses the first one that returns a certificate.
// If no certificate managers return a value, and if the config allows it
// (OnDemand!=nil) and if loadIfNecessary == true, it goes to storage to load the
// cert into the cache and serve it. If it's not on disk and if
// obtainIfNecessary == true, the certificate will be obtained from the CA, cached,
// and served. If obtainIfNecessary == true, then loadIfNecessary must also be == true.
// An error will be returned if and only if no certificate is available.
//
// This function is safe for concurrent use.
func (cfg *Config) getCertDuringHandshake(hello *tls.ClientHelloInfo, loadIfNecessary, obtainIfNecessary bool) (Certificate, error) {
	log := loggerNamed(cfg.Logger, "handshake")

	ctx := context.TODO() // TODO: get a proper context? from somewhere...

	// First check our in-memory cache to see if we've already loaded it
	cert, matched, defaulted := cfg.getCertificateFromCache(hello)
	if matched {
		if log != nil {
			log.Debug("matched certificate in cache",
				zap.Strings("subjects", cert.Names),
				zap.Bool("managed", cert.managed),
				zap.Time("expiration", cert.Leaf.NotAfter),
				zap.String("hash", cert.hash))
		}
		if cert.managed && cfg.OnDemand != nil && obtainIfNecessary {
			// On-demand certificates are maintained in the background, but
			// maintenance is triggered by handshakes instead of by a timer
			// as in maintain.go.
			return cfg.optionalMaintenance(ctx, loggerNamed(cfg.Logger, "on_demand"), cert, hello)
		}
		return cert, nil
	}

	// If an external Manager is configured, try to get it from them.
	// Only continue to use our own logic if it returns empty+nil.
	externalCert, err := cfg.getCertFromAnyCertManager(ctx, hello, log)
	if err != nil {
		return Certificate{}, err
	}
	if !externalCert.Empty() {
		return externalCert, nil
	}

	name := cfg.getNameFromClientHello(hello)

	// We might be able to load or obtain a needed certificate. Load from
	// storage if OnDemand is enabled, or if there is the possibility that
	// a statically-managed cert was evicted from a full cache.
	cfg.certCache.mu.RLock()
	cacheSize := len(cfg.certCache.cache)
	cfg.certCache.mu.RUnlock()

	// A cert might have still been evicted from the cache even if the cache
	// is no longer completely full; this happens if the newly-loaded cert is
	// itself evicted (perhaps due to being expired or unmanaged at this point).
	// Hence, we use an "almost full" metric to allow for the cache to not be
	// perfectly full while still being able to load needed certs from storage.
	// See https://caddy.community/t/error-tls-alert-internal-error-592-again/13272
	// and caddyserver/caddy#4320.
	cacheCapacity := float64(cfg.certCache.options.Capacity)
	cacheAlmostFull := cacheCapacity > 0 && float64(cacheSize) >= cacheCapacity*.9
	loadDynamically := cfg.OnDemand != nil || cacheAlmostFull

	if loadDynamically && loadIfNecessary {
		// Then check to see if we have one on disk
		// TODO: As suggested here, https://caddy.community/t/error-tls-alert-internal-error-592-again/13272/30?u=matt,
		// it might be a good idea to check with the DecisionFunc or allowlist first before even loading the certificate
		// from storage, since if we can't renew it, why should we even try serving it (it will just get evicted after
		// we get a return value of false anyway)? See issue #174
		loadedCert, err := cfg.CacheManagedCertificate(ctx, name)
		if errors.Is(err, fs.ErrNotExist) {
			// If no exact match, try a wildcard variant, which is something we can still use
			labels := strings.Split(name, ".")
			labels[0] = "*"
			loadedCert, err = cfg.CacheManagedCertificate(ctx, strings.Join(labels, "."))
		}
		if err == nil {
			if log != nil {
				log.Debug("loaded certificate from storage",
					zap.Strings("subjects", loadedCert.Names),
					zap.Bool("managed", loadedCert.managed),
					zap.Time("expiration", loadedCert.Leaf.NotAfter),
					zap.String("hash", loadedCert.hash))
			}
			loadedCert, err = cfg.handshakeMaintenance(ctx, hello, loadedCert)
			if err != nil {
				if log != nil {
					log.Error("maintaining newly-loaded certificate",
						zap.String("server_name", name),
						zap.Error(err))
				}
			}
			return loadedCert, nil
		}
		if cfg.OnDemand != nil && obtainIfNecessary {
			// By this point, we need to ask the CA for a certificate
			return cfg.obtainOnDemandCertificate(ctx, hello)
		}
	}

	// Fall back to the default certificate if there is one
	if defaulted {
		if log != nil {
			log.Debug("fell back to default certificate",
				zap.Strings("subjects", cert.Names),
				zap.Bool("managed", cert.managed),
				zap.Time("expiration", cert.Leaf.NotAfter),
				zap.String("hash", cert.hash))
		}
		return cert, nil
	}

	if log != nil {
		log.Debug("no certificate matching TLS ClientHello",
			zap.String("server_name", hello.ServerName),
			zap.String("remote", hello.Conn.RemoteAddr().String()),
			zap.String("identifier", name),
			zap.Uint16s("cipher_suites", hello.CipherSuites),
			zap.Float64("cert_cache_fill", float64(cacheSize)/cacheCapacity), // may be approximate! because we are not within the lock
			zap.Bool("load_if_necessary", loadIfNecessary),
			zap.Bool("obtain_if_necessary", obtainIfNecessary),
			zap.Bool("on_demand", cfg.OnDemand != nil))
	}

	return Certificate{}, fmt.Errorf("no certificate available for '%s'", name)
}

// optionalMaintenance will perform maintenance on the certificate (if necessary) and
// will return the resulting certificate. This should only be done if the certificate
// is managed, OnDemand is enabled, and the scope is allowed to obtain certificates.
func (cfg *Config) optionalMaintenance(ctx context.Context, log *zap.Logger, cert Certificate, hello *tls.ClientHelloInfo) (Certificate, error) {
	newCert, err := cfg.handshakeMaintenance(ctx, hello, cert)
	if err == nil {
		return newCert, nil
	}

	if log != nil {
		log.Error("renewing certificate on-demand failed",
			zap.Strings("subjects", cert.Names),
			zap.Time("not_after", cert.Leaf.NotAfter),
			zap.Error(err))
	}

	if cert.Expired() {
		return cert, err
	}

	// still has time remaining, so serve it anyway
	return cert, nil
}

// checkIfCertShouldBeObtained checks to see if an on-demand TLS certificate
// should be obtained for a given domain based upon the config settings. If
// a non-nil error is returned, do not issue a new certificate for name.
func (cfg *Config) checkIfCertShouldBeObtained(name string) error {
	if cfg.OnDemand == nil {
		return fmt.Errorf("not configured for on-demand certificate issuance")
	}
	if !SubjectQualifiesForCert(name) {
		return fmt.Errorf("subject name does not qualify for certificate: %s", name)
	}
	if cfg.OnDemand.DecisionFunc != nil {
		return cfg.OnDemand.DecisionFunc(name)
	}
	if len(cfg.OnDemand.hostWhitelist) > 0 &&
		!cfg.OnDemand.whitelistContains(name) {
		return fmt.Errorf("certificate for '%s' is not managed", name)
	}
	return nil
}

// obtainOnDemandCertificate obtains a certificate for hello.
// If another goroutine has already started obtaining a cert for
// hello, it will wait and use what the other goroutine obtained.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) obtainOnDemandCertificate(ctx context.Context, hello *tls.ClientHelloInfo) (Certificate, error) {
	log := loggerNamed(cfg.Logger, "on_demand")

	name := cfg.getNameFromClientHello(hello)

	getCertWithoutReobtaining := func() (Certificate, error) {
		// very important to set the obtainIfNecessary argument to false, so we don't repeat this infinitely
		return cfg.getCertDuringHandshake(hello, true, false)
	}

	// We must protect this process from happening concurrently, so synchronize.
	obtainCertWaitChansMu.Lock()
	wait, ok := obtainCertWaitChans[name]
	if ok {
		// lucky us -- another goroutine is already obtaining the certificate.
		// wait for it to finish obtaining the cert and then we'll use it.
		obtainCertWaitChansMu.Unlock()

		// TODO: see if we can get a proper context in here, for true cancellation
		timeout := time.NewTimer(2 * time.Minute)
		select {
		case <-timeout.C:
			return Certificate{}, fmt.Errorf("timed out waiting to obtain certificate for %s", name)
		case <-wait:
			timeout.Stop()
		}

		return getCertWithoutReobtaining()
	}

	// looks like it's up to us to do all the work and obtain the cert.
	// make a chan others can wait on if needed
	wait = make(chan struct{})
	obtainCertWaitChans[name] = wait
	obtainCertWaitChansMu.Unlock()

	unblockWaiters := func() {
		obtainCertWaitChansMu.Lock()
		close(wait)
		delete(obtainCertWaitChans, name)
		obtainCertWaitChansMu.Unlock()
	}

	// Make sure the certificate should be obtained based on config
	err := cfg.checkIfCertShouldBeObtained(name)
	if err != nil {
		unblockWaiters()
		return Certificate{}, err
	}

	if log != nil {
		log.Info("obtaining new certificate", zap.String("server_name", name))
	}

	// TODO: we are only adding a timeout because we don't know if the context passed in is actually cancelable...
	// (timeout duration is based on https://caddy.community/t/zerossl-dns-challenge-failing-often-route53-plugin/13822/24?u=matt)
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 180*time.Second)
	defer cancel()

	// Obtain the certificate
	err = cfg.ObtainCertAsync(ctx, name)

	// immediately unblock anyone waiting for it; doing this in
	// a defer would risk deadlock because of the recursive call
	// to getCertDuringHandshake below when we return!
	unblockWaiters()

	if err != nil {
		// shucks; failed to solve challenge on-demand
		return Certificate{}, err
	}

	// success; certificate was just placed on disk, so
	// we need only restart serving the certificate
	return getCertWithoutReobtaining()
}

// handshakeMaintenance performs a check on cert for expiration and OCSP validity.
// If necessary, it will renew the certificate and/or refresh the OCSP staple.
// OCSP stapling errors are not returned, only logged.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) handshakeMaintenance(ctx context.Context, hello *tls.ClientHelloInfo, cert Certificate) (Certificate, error) {
	log := loggerNamed(cfg.Logger, "on_demand")

	// Check OCSP staple validity
	if cert.ocsp != nil && !freshOCSP(cert.ocsp) {
		if log != nil {
			log.Debug("OCSP response needs refreshing",
				zap.Strings("identifiers", cert.Names),
				zap.Int("ocsp_status", cert.ocsp.Status),
				zap.Time("this_update", cert.ocsp.ThisUpdate),
				zap.Time("next_update", cert.ocsp.NextUpdate))
		}

		err := stapleOCSP(ctx, cfg.OCSP, cfg.Storage, &cert, nil)
		if err != nil {
			// An error with OCSP stapling is not the end of the world, and in fact, is
			// quite common considering not all certs have issuer URLs that support it.
			if log != nil {
				log.Warn("stapling OCSP",
					zap.String("server_name", hello.ServerName),
					zap.Error(err))
			}
		} else if log != nil {
			if log != nil {
				log.Debug("successfully stapled new OCSP response",
					zap.Strings("identifiers", cert.Names),
					zap.Int("ocsp_status", cert.ocsp.Status),
					zap.Time("this_update", cert.ocsp.ThisUpdate),
					zap.Time("next_update", cert.ocsp.NextUpdate))
			}
		}

		// our copy of cert has the new OCSP staple, so replace it in the cache
		cfg.certCache.mu.Lock()
		cfg.certCache.cache[cert.hash] = cert
		cfg.certCache.mu.Unlock()
	}

	// We attempt to replace any certificates that were revoked.
	// Crucially, this happens OUTSIDE a lock on the certCache.
	if certShouldBeForceRenewed(cert) {
		if log != nil {
			log.Warn("on-demand certificate's OCSP status is REVOKED; will try to forcefully renew",
				zap.Strings("identifiers", cert.Names),
				zap.Int("ocsp_status", cert.ocsp.Status),
				zap.Time("revoked_at", cert.ocsp.RevokedAt),
				zap.Time("this_update", cert.ocsp.ThisUpdate),
				zap.Time("next_update", cert.ocsp.NextUpdate))
		}
		return cfg.renewDynamicCertificate(ctx, hello, cert)
	}

	// Check cert expiration
	if currentlyInRenewalWindow(cert.Leaf.NotBefore, cert.Leaf.NotAfter, cfg.RenewalWindowRatio) {
		return cfg.renewDynamicCertificate(ctx, hello, cert)
	}

	return cert, nil
}

// renewDynamicCertificate renews the certificate for name using cfg. It returns the
// certificate to use and an error, if any. name should already be lower-cased before
// calling this function. name is the name obtained directly from the handshake's
// ClientHello. If the certificate hasn't yet expired, currentCert will be returned
// and the renewal will happen in the background; otherwise this blocks until the
// certificate has been renewed, and returns the renewed certificate.
//
// If the certificate's OCSP status (currentCert.ocsp) is Revoked, it will be forcefully
// renewed even if it is not expiring.
//
// This function is safe for use by multiple concurrent goroutines.
func (cfg *Config) renewDynamicCertificate(ctx context.Context, hello *tls.ClientHelloInfo, currentCert Certificate) (Certificate, error) {
	log := loggerNamed(cfg.Logger, "on_demand")

	name := cfg.getNameFromClientHello(hello)
	timeLeft := time.Until(currentCert.Leaf.NotAfter)
	revoked := currentCert.ocsp != nil && currentCert.ocsp.Status == ocsp.Revoked

	getCertWithoutReobtaining := func() (Certificate, error) {
		// very important to set the obtainIfNecessary argument to false, so we don't repeat this infinitely
		return cfg.getCertDuringHandshake(hello, true, false)
	}

	// see if another goroutine is already working on this certificate
	obtainCertWaitChansMu.Lock()
	wait, ok := obtainCertWaitChans[name]
	if ok {
		// lucky us -- another goroutine is already renewing the certificate
		obtainCertWaitChansMu.Unlock()

		// the current certificate hasn't expired, and another goroutine is already
		// renewing it, so we might as well serve what we have without blocking, UNLESS
		// we're forcing renewal, in which case the current certificate is not usable
		if timeLeft > 0 && !revoked {
			if log != nil {
				log.Debug("certificate expires soon but is already being renewed; serving current certificate",
					zap.Strings("subjects", currentCert.Names),
					zap.Duration("remaining", timeLeft))
			}
			return currentCert, nil
		}

		// otherwise, we'll have to wait for the renewal to finish so we don't serve
		// a revoked or expired certificate

		if log != nil {
			log.Debug("certificate has expired, but is already being renewed; waiting for renewal to complete",
				zap.Strings("subjects", currentCert.Names),
				zap.Time("expired", currentCert.Leaf.NotAfter),
				zap.Bool("revoked", revoked))
		}

		// TODO: see if we can get a proper context in here, for true cancellation
		timeout := time.NewTimer(2 * time.Minute)
		select {
		case <-timeout.C:
			return Certificate{}, fmt.Errorf("timed out waiting for certificate renewal of %s", name)
		case <-wait:
			timeout.Stop()
		}

		return getCertWithoutReobtaining()
	}

	// looks like it's up to us to do all the work and renew the cert
	wait = make(chan struct{})
	obtainCertWaitChans[name] = wait
	obtainCertWaitChansMu.Unlock()

	unblockWaiters := func() {
		obtainCertWaitChansMu.Lock()
		close(wait)
		delete(obtainCertWaitChans, name)
		obtainCertWaitChansMu.Unlock()
	}

	if log != nil {
		log.Info("attempting certificate renewal",
			zap.String("server_name", name),
			zap.Strings("subjects", currentCert.Names),
			zap.Time("expiration", currentCert.Leaf.NotAfter),
			zap.Duration("remaining", timeLeft),
			zap.Bool("revoked", revoked))
	}

	// Make sure a certificate for this name should be obtained on-demand
	err := cfg.checkIfCertShouldBeObtained(name)
	if err != nil {
		// if not, remove from cache (it will be deleted from storage later)
		cfg.certCache.mu.Lock()
		cfg.certCache.removeCertificate(currentCert)
		cfg.certCache.mu.Unlock()
		unblockWaiters()
		return Certificate{}, err
	}

	// Renew and reload the certificate
	renewAndReload := func(ctx context.Context, cancel context.CancelFunc) (Certificate, error) {
		defer cancel()

		// otherwise, renew with issuer, etc.
		var newCert Certificate
		if revoked {
			newCert, err = cfg.forceRenew(ctx, log, currentCert)
		} else {
			err = cfg.RenewCertAsync(ctx, name, false)
			if err == nil {
				// even though the recursive nature of the dynamic cert loading
				// would just call this function anyway, we do it here to
				// make the replacement as atomic as possible.
				newCert, err = cfg.CacheManagedCertificate(ctx, name)
				if err != nil {
					if log != nil {
						log.Error("loading renewed certificate", zap.String("server_name", name), zap.Error(err))
					}
				} else {
					// replace the old certificate with the new one
					cfg.certCache.replaceCertificate(currentCert, newCert)
				}
			}
		}

		// immediately unblock anyone waiting for it; doing this in
		// a defer would risk deadlock because of the recursive call
		// to getCertDuringHandshake below when we return!
		unblockWaiters()

		if err != nil {
			if log != nil {
				log.Error("renewing and reloading certificate",
					zap.String("server_name", name),
					zap.Error(err),
					zap.Bool("forced", revoked))
			}
			return newCert, err
		}

		return getCertWithoutReobtaining()
	}

	// if the certificate hasn't expired, we can serve what we have and renew in the background
	if timeLeft > 0 {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		go renewAndReload(ctx, cancel)
		return currentCert, nil
	}

	// otherwise, we have to block while we renew an expired certificate
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	return renewAndReload(ctx, cancel)
}

// getCertFromAnyCertManager gets a certificate from cfg's Managers. If there are no Managers defined, this is
// a no-op that returns empty values. Otherwise, it gets a certificate for hello from the first Manager that
// returns a certificate and no error.
func (cfg *Config) getCertFromAnyCertManager(ctx context.Context, hello *tls.ClientHelloInfo, log *zap.Logger) (Certificate, error) {
	// fast path if nothing to do
	if len(cfg.Managers) == 0 {
		return Certificate{}, nil
	}

	var upstreamCert *tls.Certificate

	// try all the GetCertificate methods on external managers; use first one that returns a certificate
	for i, certManager := range cfg.Managers {
		var err error
		upstreamCert, err = certManager.GetCertificate(ctx, hello)
		if err != nil {
			log.Error("getting certificate from external certificate manager",
				zap.String("sni", hello.ServerName),
				zap.Int("cert_manager", i),
				zap.Error(err))
			continue
		}
		if upstreamCert != nil {
			break
		}
	}
	if upstreamCert == nil {
		if log != nil {
			log.Debug("all external certificate managers yielded no certificates and no errors", zap.String("sni", hello.ServerName))
		}
		return Certificate{}, nil
	}

	var cert Certificate
	err := fillCertFromLeaf(&cert, *upstreamCert)
	if err != nil {
		return Certificate{}, fmt.Errorf("external certificate manager: %s: filling cert from leaf: %v", hello.ServerName, err)
	}

	if log != nil {
		log.Debug("using externally-managed certificate",
			zap.String("sni", hello.ServerName),
			zap.Strings("names", cert.Names),
			zap.Time("expiration", cert.Leaf.NotAfter))
	}

	return cert, nil
}

// getTLSALPNChallengeCert is to be called when the clientHello pertains to
// a TLS-ALPN challenge and a certificate is required to solve it. This method gets
// the relevant challenge info and then returns the associated certificate (if any)
// or generates it anew if it's not available (as is the case when distributed
// solving). True is returned if the challenge is being solved distributed (there
// is no semantic difference with distributed solving; it is mainly for logging).
func (cfg *Config) getTLSALPNChallengeCert(clientHello *tls.ClientHelloInfo) (*tls.Certificate, bool, error) {
	chalData, distributed, err := cfg.getChallengeInfo(clientHello.Context(), clientHello.ServerName)
	if err != nil {
		return nil, distributed, err
	}

	// fast path: we already created the certificate (this avoids having to re-create
	// it at every handshake that tries to verify, e.g. multi-perspective validation)
	if chalData.data != nil {
		return chalData.data.(*tls.Certificate), distributed, nil
	}

	// otherwise, we can re-create the solution certificate, but it takes a few cycles
	cert, err := acmez.TLSALPN01ChallengeCert(chalData.Challenge)
	if err != nil {
		return nil, distributed, fmt.Errorf("making TLS-ALPN challenge certificate: %v", err)
	}
	if cert == nil {
		return nil, distributed, fmt.Errorf("got nil TLS-ALPN challenge certificate but no error")
	}

	return cert, distributed, nil
}

// getNameFromClientHello returns a normalized form of hello.ServerName.
// If hello.ServerName is empty (i.e. client did not use SNI), then the
// associated connection's local address is used to extract an IP address.
func (*Config) getNameFromClientHello(hello *tls.ClientHelloInfo) string {
	if name := normalizedName(hello.ServerName); name != "" {
		return name
	}
	return localIPFromConn(hello.Conn)
}

// localIPFromConn returns the host portion of c's local address
// and strips the scope ID if one exists (see RFC 4007).
func localIPFromConn(c net.Conn) string {
	if c == nil {
		return ""
	}
	localAddr := c.LocalAddr().String()
	ip, _, err := net.SplitHostPort(localAddr)
	if err != nil {
		// OK; assume there was no port
		ip = localAddr
	}
	// IPv6 addresses can have scope IDs, e.g. "fe80::4c3:3cff:fe4f:7e0b%eth0",
	// but for our purposes, these are useless (unless a valid use case proves
	// otherwise; see issue #3911)
	if scopeIDStart := strings.Index(ip, "%"); scopeIDStart > -1 {
		ip = ip[:scopeIDStart]
	}
	return ip
}

// normalizedName returns a cleaned form of serverName that is
// used for consistency when referring to a SNI value.
func normalizedName(serverName string) string {
	return strings.ToLower(strings.TrimSpace(serverName))
}

// obtainCertWaitChans is used to coordinate obtaining certs for each hostname.
var obtainCertWaitChans = make(map[string]chan struct{})
var obtainCertWaitChansMu sync.Mutex
