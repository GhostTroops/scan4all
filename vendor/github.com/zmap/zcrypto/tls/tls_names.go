// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"strconv"
	"strings"
)

var signatureNames map[uint8]string
var hashNames map[uint8]string
var cipherSuiteNames map[int]string
var compressionNames map[uint8]string
var curveNames map[uint16]string
var pointFormatNames map[uint8]string
var clientAuthTypeNames map[int]string
var signatureSchemeNames map[uint16]string

func init() {
	// RFC 5246 7.4.1.4.1
	signatureNames = make(map[uint8]string, 8)
	// TODO FIXME: the RFC also defines anonymous(0) and (255).
	signatureNames[signatureRSA] = "rsa"
	signatureNames[signatureDSA] = "dsa"
	signatureNames[signatureECDSA] = "ecdsa"

	// RFC 5246 7.4.1.4.1
	hashNames = make(map[uint8]string, 16)
	// TODO FIXME: the RFC also defines none(0) and (255).
	hashNames[hashMD5] = "md5"
	hashNames[hashSHA1] = "sha1"
	hashNames[hashSHA224] = "sha224"
	hashNames[hashSHA256] = "sha256"
	hashNames[hashSHA384] = "sha384"
	hashNames[hashSHA512] = "sha512"

	cipherSuiteNames = make(map[int]string, 512)
	cipherSuiteNames[0x0000] = "TLS_NULL_WITH_NULL_NULL"
	cipherSuiteNames[0x0001] = "TLS_RSA_WITH_NULL_MD5"
	cipherSuiteNames[0x0002] = "TLS_RSA_WITH_NULL_SHA"
	cipherSuiteNames[0x0003] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
	cipherSuiteNames[0x0004] = "TLS_RSA_WITH_RC4_128_MD5"
	cipherSuiteNames[0x0005] = "TLS_RSA_WITH_RC4_128_SHA"
	cipherSuiteNames[0x0006] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"
	cipherSuiteNames[0x0007] = "TLS_RSA_WITH_IDEA_CBC_SHA"
	cipherSuiteNames[0x0008] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
	cipherSuiteNames[0x0009] = "TLS_RSA_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x000A] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x000B] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"
	cipherSuiteNames[0x000C] = "TLS_DH_DSS_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x000D] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x000E] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"
	cipherSuiteNames[0x000F] = "TLS_DH_RSA_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x0010] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x0011] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"
	cipherSuiteNames[0x0012] = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x0013] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x0014] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
	cipherSuiteNames[0x0015] = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x0016] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x0017] = "TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5"
	cipherSuiteNames[0x0018] = "TLS_DH_ANON_WITH_RC4_128_MD5"
	cipherSuiteNames[0x0019] = "TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA"
	cipherSuiteNames[0x001A] = "TLS_DH_ANON_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x001B] = "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x001C] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA"
	cipherSuiteNames[0x001D] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"
	cipherSuiteNames[0x001E] = "TLS_KRB5_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x001F] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x0020] = "TLS_KRB5_WITH_RC4_128_SHA"
	cipherSuiteNames[0x0021] = "TLS_KRB5_WITH_IDEA_CBC_SHA"
	cipherSuiteNames[0x0022] = "TLS_KRB5_WITH_DES_CBC_MD5"
	cipherSuiteNames[0x0023] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"
	cipherSuiteNames[0x0024] = "TLS_KRB5_WITH_RC4_128_MD5"
	cipherSuiteNames[0x0025] = "TLS_KRB5_WITH_IDEA_CBC_MD5"
	cipherSuiteNames[0x0026] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"
	cipherSuiteNames[0x0027] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"
	cipherSuiteNames[0x0028] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"
	cipherSuiteNames[0x0029] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
	cipherSuiteNames[0x002A] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"
	cipherSuiteNames[0x002B] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
	cipherSuiteNames[0x002C] = "TLS_PSK_WITH_NULL_SHA"
	cipherSuiteNames[0x002D] = "TLS_DHE_PSK_WITH_NULL_SHA"
	cipherSuiteNames[0x002E] = "TLS_RSA_PSK_WITH_NULL_SHA"
	cipherSuiteNames[0x002F] = "TLS_RSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0030] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0031] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0032] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0033] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0034] = "TLS_DH_ANON_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0035] = "TLS_RSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0036] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0037] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0038] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0039] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x003A] = "TLS_DH_ANON_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x003B] = "TLS_RSA_WITH_NULL_SHA256"
	cipherSuiteNames[0x003C] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x003D] = "TLS_RSA_WITH_AES_256_CBC_SHA256"
	cipherSuiteNames[0x003E] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x003F] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x0040] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x0041] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
	cipherSuiteNames[0x0042] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"
	cipherSuiteNames[0x0043] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"
	cipherSuiteNames[0x0044] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
	cipherSuiteNames[0x0045] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
	cipherSuiteNames[0x0046] = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA"
	cipherSuiteNames[0x0047] = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
	cipherSuiteNames[0x0048] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
	cipherSuiteNames[0x0049] = "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x004A] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x004B] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x004C] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0060] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"
	cipherSuiteNames[0x0061] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"
	cipherSuiteNames[0x0062] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x0063] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"
	cipherSuiteNames[0x0064] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"
	cipherSuiteNames[0x0065] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"
	cipherSuiteNames[0x0066] = "TLS_DHE_DSS_WITH_RC4_128_SHA"
	cipherSuiteNames[0x0067] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x0068] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
	cipherSuiteNames[0x0069] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
	cipherSuiteNames[0x006A] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
	cipherSuiteNames[0x006B] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	cipherSuiteNames[0x006C] = "TLS_DH_ANON_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x006D] = "TLS_DH_ANON_WITH_AES_256_CBC_SHA256"
	cipherSuiteNames[0x0080] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT"
	cipherSuiteNames[0x0081] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT"
	cipherSuiteNames[0x0082] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411"
	cipherSuiteNames[0x0083] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411"
	cipherSuiteNames[0x0084] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
	cipherSuiteNames[0x0085] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"
	cipherSuiteNames[0x0086] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"
	cipherSuiteNames[0x0087] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
	cipherSuiteNames[0x0088] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
	cipherSuiteNames[0x0089] = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA"
	cipherSuiteNames[0x008A] = "TLS_PSK_WITH_RC4_128_SHA"
	cipherSuiteNames[0x008B] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x008C] = "TLS_PSK_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x008D] = "TLS_PSK_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x008E] = "TLS_DHE_PSK_WITH_RC4_128_SHA"
	cipherSuiteNames[0x008F] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x0090] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0091] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0092] = "TLS_RSA_PSK_WITH_RC4_128_SHA"
	cipherSuiteNames[0x0093] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0x0094] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0x0095] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0x0096] = "TLS_RSA_WITH_SEED_CBC_SHA"
	cipherSuiteNames[0x0097] = "TLS_DH_DSS_WITH_SEED_CBC_SHA"
	cipherSuiteNames[0x0098] = "TLS_DH_RSA_WITH_SEED_CBC_SHA"
	cipherSuiteNames[0x0099] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
	cipherSuiteNames[0x009A] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
	cipherSuiteNames[0x009B] = "TLS_DH_ANON_WITH_SEED_CBC_SHA"
	cipherSuiteNames[0x009C] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x009D] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x009E] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x009F] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00A0] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00A1] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00A2] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00A3] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00A4] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00A5] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00A6] = "TLS_DH_ANON_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00A7] = "TLS_DH_ANON_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00A8] = "TLS_PSK_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00A9] = "TLS_PSK_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00AA] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00AB] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00AC] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0x00AD] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0x00AE] = "TLS_PSK_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x00AF] = "TLS_PSK_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0x00B0] = "TLS_PSK_WITH_NULL_SHA256"
	cipherSuiteNames[0x00B1] = "TLS_PSK_WITH_NULL_SHA384"
	cipherSuiteNames[0x00B2] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x00B3] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0x00B4] = "TLS_DHE_PSK_WITH_NULL_SHA256"
	cipherSuiteNames[0x00B5] = "TLS_DHE_PSK_WITH_NULL_SHA384"
	cipherSuiteNames[0x00B6] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0x00B7] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0x00B8] = "TLS_RSA_PSK_WITH_NULL_SHA256"
	cipherSuiteNames[0x00B9] = "TLS_RSA_PSK_WITH_NULL_SHA384"
	cipherSuiteNames[0x00BA] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0x00BB] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0x00BC] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0x00BD] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0x00BE] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0x00BF] = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0x00C0] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
	cipherSuiteNames[0x00C1] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"
	cipherSuiteNames[0x00C2] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"
	cipherSuiteNames[0x00C3] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
	cipherSuiteNames[0x00C4] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
	cipherSuiteNames[0x00C5] = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256"
	cipherSuiteNames[0x00FF] = "TLS_RENEGO_PROTECTION_REQUEST"
	cipherSuiteNames[0x5600] = "TLS_FALLBACK_SCSV"
	cipherSuiteNames[0xC001] = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
	cipherSuiteNames[0xC002] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
	cipherSuiteNames[0xC003] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC004] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC005] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC006] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
	cipherSuiteNames[0xC007] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	cipherSuiteNames[0xC008] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC00A] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC00B] = "TLS_ECDH_RSA_WITH_NULL_SHA"
	cipherSuiteNames[0xC00C] = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
	cipherSuiteNames[0xC00D] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC00E] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC00F] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC010] = "TLS_ECDHE_RSA_WITH_NULL_SHA"
	cipherSuiteNames[0xC011] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	cipherSuiteNames[0xC012] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC015] = "TLS_ECDH_ANON_WITH_NULL_SHA"
	cipherSuiteNames[0xC016] = "TLS_ECDH_ANON_WITH_RC4_128_SHA"
	cipherSuiteNames[0xC017] = "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC018] = "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC019] = "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC01A] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC01B] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC01C] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC01D] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC01E] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC01F] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC020] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC021] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC022] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0xC024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0xC025] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0xC026] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0xC028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0xC029] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0xC02A] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0xC02D] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0xC02E] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0xC030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0xC031] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0xC032] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
	cipherSuiteNames[0xC033] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
	cipherSuiteNames[0xC034] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xC035] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
	cipherSuiteNames[0xC036] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
	cipherSuiteNames[0xC037] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
	cipherSuiteNames[0xC038] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
	cipherSuiteNames[0xC039] = "TLS_ECDHE_PSK_WITH_NULL_SHA"
	cipherSuiteNames[0xC03A] = "TLS_ECDHE_PSK_WITH_NULL_SHA256"
	cipherSuiteNames[0xC03B] = "TLS_ECDHE_PSK_WITH_NULL_SHA384"
	cipherSuiteNames[0xC03C] = "TLS_RSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC03D] = "TLS_RSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC03E] = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC03F] = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC040] = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC041] = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC042] = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC043] = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC044] = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC045] = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC046] = "TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC047] = "TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC048] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC049] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC04A] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC04B] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC04C] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC04D] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC04E] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC04F] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC050] = "TLS_RSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC051] = "TLS_RSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC052] = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC053] = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC054] = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC055] = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC056] = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC057] = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC058] = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC059] = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC05A] = "TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC05B] = "TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC05C] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC05D] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC05E] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC05F] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC060] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC061] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC062] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC063] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC064] = "TLS_PSK_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC065] = "TLS_PSK_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC066] = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC067] = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC068] = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC069] = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC06A] = "TLS_PSK_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC06B] = "TLS_PSK_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC06C] = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC06D] = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC06E] = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"
	cipherSuiteNames[0xC06F] = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"
	cipherSuiteNames[0xC070] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"
	cipherSuiteNames[0xC071] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"
	cipherSuiteNames[0xC072] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC073] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC074] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC075] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC076] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC077] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC078] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC079] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC07A] = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC07B] = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC07C] = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC07D] = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC07E] = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC07F] = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC080] = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC081] = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC082] = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC083] = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC084] = "TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC085] = "TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC086] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC087] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC088] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC089] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC08A] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC08B] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC08C] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC08D] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC08E] = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC08F] = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC090] = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC091] = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC092] = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"
	cipherSuiteNames[0xC093] = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"
	cipherSuiteNames[0xC094] = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC095] = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC096] = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC097] = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC098] = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC099] = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC09A] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"
	cipherSuiteNames[0xC09B] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"
	cipherSuiteNames[0xC09C] = "TLS_RSA_WITH_AES_128_CCM"
	cipherSuiteNames[0xC09D] = "TLS_RSA_WITH_AES_256_CCM"
	cipherSuiteNames[0xC09E] = "TLS_DHE_RSA_WITH_AES_128_CCM"
	cipherSuiteNames[0xC09F] = "TLS_DHE_RSA_WITH_AES_256_CCM"
	cipherSuiteNames[0xC0A0] = "TLS_RSA_WITH_AES_128_CCM_8"
	cipherSuiteNames[0xC0A1] = "TLS_RSA_WITH_AES_256_CCM_8"
	cipherSuiteNames[0xC0A2] = "TLS_DHE_RSA_WITH_AES_128_CCM_8"
	cipherSuiteNames[0xC0A3] = "TLS_DHE_RSA_WITH_AES_256_CCM_8"
	cipherSuiteNames[0xC0A4] = "TLS_PSK_WITH_AES_128_CCM"
	cipherSuiteNames[0xC0A5] = "TLS_PSK_WITH_AES_256_CCM"
	cipherSuiteNames[0xC0A6] = "TLS_DHE_PSK_WITH_AES_128_CCM"
	cipherSuiteNames[0xC0A7] = "TLS_DHE_PSK_WITH_AES_256_CCM"
	cipherSuiteNames[0xC0A8] = "TLS_PSK_WITH_AES_128_CCM_8"
	cipherSuiteNames[0xC0A9] = "TLS_PSK_WITH_AES_256_CCM_8"
	cipherSuiteNames[0xC0AA] = "TLS_PSK_DHE_WITH_AES_128_CCM_8"
	cipherSuiteNames[0xC0AB] = "TLS_PSK_DHE_WITH_AES_256_CCM_8"
	cipherSuiteNames[0xC0AC] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
	cipherSuiteNames[0xC0AD] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
	cipherSuiteNames[0xC0AE] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
	cipherSuiteNames[0xC0AF] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
	cipherSuiteNames[0xCAFE] = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"
	cipherSuiteNames[0xCC13] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD"
	cipherSuiteNames[0xCC14] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD"
	cipherSuiteNames[0xCC15] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD"
	cipherSuiteNames[0xCCA8] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	cipherSuiteNames[0xCCA9] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	cipherSuiteNames[0xCCAA] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	cipherSuiteNames[0xFEFE] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
	cipherSuiteNames[0xFEFF] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xFFE0] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
	cipherSuiteNames[0xFFE1] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
	cipherSuiteNames[0xFF80] = "SSL_RSA_WITH_RC2_CBC_MD5"
	cipherSuiteNames[0xFF81] = "SSL_RSA_WITH_IDEA_CBC_MD5"
	cipherSuiteNames[0xFF82] = "SSL_RSA_WITH_DES_CBC_MD5"
	cipherSuiteNames[0xFF83] = "SSL_RSA_WITH_3DES_EDE_CBC_MD5"
	cipherSuiteNames[0xFF03] = "SSL_EN_RC2_128_CBC_WITH_MD5"
	cipherSuiteNames[0xFF85] = "OP_PCL_TLS10_AES_128_CBC_SHA512"

	// https://www.iana.org/assignments/comp-meth-ids/comp-meth-ids.xhtml#comp-meth-ids-2
	compressionNames = make(map[uint8]string)
	compressionNames[0] = "NULL"
	compressionNames[1] = "DEFLATE"
	compressionNames[64] = "LZS"

	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
	curveNames = make(map[uint16]string)
	curveNames[1] = "sect163k1"
	curveNames[2] = "sect163r1"
	curveNames[3] = "sect163r2"
	curveNames[4] = "sect193r1"
	curveNames[5] = "sect193r2"
	curveNames[6] = "sect233k1"
	curveNames[7] = "sect233r1"
	curveNames[8] = "sect239k1"
	curveNames[9] = "sect283k1"
	curveNames[10] = "sect283r1"
	curveNames[11] = "sect409k1"
	curveNames[12] = "sect409r1"
	curveNames[13] = "sect571k1"
	curveNames[14] = "sect571r1"
	curveNames[15] = "secp160k1"
	curveNames[16] = "secp160r1"
	curveNames[17] = "secp160r2"
	curveNames[18] = "secp192k1"
	curveNames[19] = "secp192r1"
	curveNames[20] = "secp224k1"
	curveNames[21] = "secp224r1"
	curveNames[22] = "secp256k1"
	curveNames[23] = "secp256r1"
	curveNames[24] = "secp384r1"
	curveNames[25] = "secp521r1"
	curveNames[26] = "brainpoolP256r1"
	curveNames[27] = "brainpoolP384r1"
	curveNames[28] = "brainpoolP512r1"
	curveNames[29] = "ecdh_x25519" // TEMPORARY -- expires 1Mar2018
	curveNames[30] = "ecdh_x448"   // TEMPORARY -- expires 1Mar2018
	curveNames[256] = "ffdhe2048"
	curveNames[257] = "ffdhe3072"
	curveNames[258] = "ffdhe4096"
	curveNames[259] = "ffdhe6144"
	curveNames[260] = "ffdhe8192"
	curveNames[65281] = "arbitrary_explicit_prime_curves"
	curveNames[65282] = "arbitrary_explicit_char2_curves"

	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
	pointFormatNames = make(map[uint8]string)
	pointFormatNames[0] = "uncompressed"
	pointFormatNames[1] = "ansiX962_compressed_prime"
	pointFormatNames[2] = "ansiX962_compressed_char2"

	// Name-value paires *are* not standardized, only dereferenced for JSON output
	clientAuthTypeNames = make(map[int]string)
	clientAuthTypeNames[0] = "NoClientCert"
	clientAuthTypeNames[1] = "RequestClientCert"
	clientAuthTypeNames[2] = "RequireAnyClientCert"
	clientAuthTypeNames[3] = "VerifyClientCertIfGiven"
	clientAuthTypeNames[4] = "RequireAndVerifyClientCert"

	// https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-4.2.3
	signatureSchemeNames = make(map[uint16]string)
	signatureSchemeNames[uint16(PKCS1WithSHA1)] = "rsa_pkcs1_sha1"
	signatureSchemeNames[uint16(PKCS1WithSHA256)] = "rsa_pkcs1_sha256"
	signatureSchemeNames[uint16(PKCS1WithSHA384)] = "rsa_pkcs1_sha384"
	signatureSchemeNames[uint16(PKCS1WithSHA512)] = "rsa_pkcs1_sha512"
	signatureSchemeNames[uint16(PSSWithSHA256)] = "rsa_pss_sha256"
	signatureSchemeNames[uint16(PSSWithSHA384)] = "rsa_pss_sha384"
	signatureSchemeNames[uint16(PSSWithSHA512)] = "rsa_pss_sha512"
	signatureSchemeNames[uint16(ECDSAWithP256AndSHA256)] = "ecdsa_secp256r1_sha256"
	signatureSchemeNames[uint16(ECDSAWithP384AndSHA384)] = "ecdsa_secp384r1_sha384"
	signatureSchemeNames[uint16(ECDSAWithP521AndSHA512)] = "ecdsa_secp521r1_sha512"
	signatureSchemeNames[uint16(EdDSAWithEd25519)] = "ed25519"
	signatureSchemeNames[uint16(EdDSAWithEd448)] = "ed448"
}

func nameForSignature(s uint8) string {
	if name, ok := signatureNames[s]; ok {
		return name
	}
	return "unknown." + strconv.Itoa(int(s))
}

func nameForHash(h uint8) string {
	if name, ok := hashNames[h]; ok {
		return name
	}
	num := strconv.Itoa(int(h))
	return "unknown." + num
}

func signatureToName(n string) uint8 {
	for k, v := range signatureNames {
		if v == n {
			return k
		}
	}
	s, _ := strconv.ParseInt(strings.TrimPrefix(n, "unknown."), 10, 32)
	return uint8(s)
}

func hashToName(n string) uint8 {
	for k, v := range hashNames {
		if v == n {
			return k
		}
	}
	h, _ := strconv.ParseInt(strings.TrimPrefix(n, "unknown."), 10, 32)
	return uint8(h)
}

func nameForSuite(cs uint16) string {
	cipher := CipherSuite(cs)
	return cipher.String()
}

func (cs CipherSuite) Bytes() []byte {
	return []byte{uint8(cs >> 8), uint8(cs)}
}

func (cs CipherSuite) String() string {
	if name, ok := cipherSuiteNames[int(cs)]; ok {
		return name
	}
	return "unknown"
}

func (cm CompressionMethod) String() string {
	if name, ok := compressionNames[uint8(cm)]; ok {
		return name
	}
	return "unknown"
}

func (curveID CurveID) String() string {
	if name, ok := curveNames[uint16(curveID)]; ok {
		return name
	}
	return "unknown"
}

func (pFormat PointFormat) String() string {
	if name, ok := pointFormatNames[uint8(pFormat)]; ok {
		return name
	}
	return "unknown"
}

func nameForCompressionMethod(cm uint8) string {
	compressionMethod := CompressionMethod(cm)
	return compressionMethod.String()
}

func nameForCurve(curveID uint16) string {
	curve := CurveID(curveID)
	return curve.String()
}

func nameForPointFormat(pFormat uint8) string {
	format := PointFormat(pFormat)
	return format.String()
}

func (v TLSVersion) Bytes() []byte {
	return []byte{uint8(v >> 8), uint8(v)}
}

func (v TLSVersion) String() string {
	switch v {
	case 0x0300:
		return "SSLv3"
	case 0x0301:
		return "TLSv1.0"
	case 0x0302:
		return "TLSv1.1"
	case 0x0303:
		return "TLSv1.2"
	default:
		return "unknown"
	}
}

func nameForSignatureScheme(scheme uint16) string {
	sigScheme := SignatureScheme(scheme)
	return sigScheme.String()
}

func (sigScheme *SignatureScheme) String() string {
	if name, ok := signatureSchemeNames[uint16(*sigScheme)]; ok {
		return name
	}
	return "unknown"
}

func (sigScheme *SignatureScheme) Bytes() []byte {
	return []byte{byte(*sigScheme >> 8), byte(*sigScheme)}
}
