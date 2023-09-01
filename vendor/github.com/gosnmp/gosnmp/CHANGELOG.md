## unreleased

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## v1.36.0

This release now requires Go 1.20 or higher.

* [ENHANCEMENT] Allow sending v1 traps that have no varbinds #426
* [BUGFIX] Fix getBulk SnmpPacket MaxRepetitions value #413
* [BUGFIX] Refactor security logger #422
* [BUGFIX] Add privacy passphrase in extendKeyBlumenthal cacheKey call #425
* [BUGFIX] unmarshal: fix panic from reading beyond slice #441

## v1.35.0

This release now requires Go 1.17 or higher.

NOTE: The UnmarshalTrap now returns both an SnmpPacket and an error (#394)

* [BUGFIX] gosnmp.Set(): permit ObjectIdentifier PDU Type #378
* [BUGFIX] SendTrap: do not set Reportable MsgFlags for v3 #398
* [CHANGE] Support authoritative engineID discovery when listening for traps #394
* [CHANGE] Require Go 1.17+
* [ENHANCEMENT] marshalUint32: Values above 2^31-1 encodes in 5 bytes #377
* [ENHANCEMENT] Add Control function to GoSNMP dialer parameters #397

## v1.34.0

NOTE: marshalInt32 now always encodes an integer value in the smallest possible
number of octets as per ITU-T Rec. X.690 (07/2002).

* [ENHANCEMENT] gosnmp/marshalInt32: adhere to ITU-T Rec. X.690 integer encoding #372
* [ENHANCEMENT] parseInt64: throw error on zero length as per X690 #373
* [ENHANCEMENT] helper.go: Interpreting the value of an Opaque type as binary data if the Opaque sub-type cannot be recognized #374
* [ENHANCEMENT] helper.go: Implemented Opaque type marshaling #374
* [BUGFIX] marshal.go: Fixed invalid OpaqueFloat and OpaqueDouble marshaling in marshalVarbind() function #374
* [BUGFIX] marshal.go: stricter cursor bounds checking in unmarshalPayload #384

## v1.33.0

* [BUGFIX] parseLength: avoid OOB read, prevent panic #354
* [BUGFIX] Detect negative lengths in parseLength, prevent panic #369
* [FEATURE] Add LocalAddr setting to bind source address of SNMP queries #342
* [ENHANCEMENT] Validate SNMPv3 Auth/Priv Protocol for incoming trap message #351
* [ENHANCEMENT] helper.go: add error handling to parseLength #358
* [ENHANCEMENT] Rename v3_testing_credentials to avoid testing import in prod builds #360
* [ENHANCEMENT] helper.go: Improved decodeValue() function #340

## v1.32.0

NOTE: This release changes the Logger interface. The loggingEnabled variable has been deprecated.

* [BUGFIX] marshal.go: improve packet validation and error handling #323
* [BUGFIX] marshal.go: Fix on-error-continue flow in sendOneRequest #324
* [BUGFIX] Fix SNMPv3 trap authentication #332
* [CHANGE] New Logger interface has been implemented #329
* [ENHANCEMENT] helper.go: Improved OID marshaling with sub-identifier validation as per rfc2578 section-3.5 #321
* [ENHANCEMENT] Add rfc3412 report errors #333

## v1.31.0

* [BUGFIX] Add validation to prevent calling updatePktSecurityParameters with non v3 packet #251 #314
* [ENHANCEMENT] walk.go: improve BulkWalk error handling #306
* [ENHANCEMENT] return received SNMP error code immediately instead of waiting for timeout #319

## v1.30.0

NOTE: This release changes the MaxRepetitions type to uint32.

* [BUGFIX] Add bounds checking for reqID and msgID #273
* [FEATURE] New packet inspection hook methods for in-flight measurements #276
* [ENHANCEMENT] Support for local e2e tests against net-snmpd #292
* [CHANGE] Fix GetBulkRequest MaxRepetitions signedness issue in marshalPDU() #293
* [CHANGE] mocks/gosnmp_mock.go: Update UnmarshalTrap mock base method #294
* [BUGFIX] marshal.go: Fix signedness issue in marshalPDU() #295
* [ENHANCEMENT] marshalPDU(): stricter integer conversion #301
* [ENHANCEMENT] Use Go 1.13 error wrapping #304
* [ENHANCEMENT] walk.go: improve BulkWalk error handling #306
* [ENHANCEMENT] MaxRepetitions now allows values between 0..2147483647 and wraps to 0 at max int32.

## v1.29.0

NOTE: This release returns the OctetString []byte behavior for v1.26.0 and earlier.

* [CHANGE] Return OctetString as []byte #264

## v1.28.0

This release updates the Go import path from `github.com/soniah/gosnmp`
to `github.com/gosnmp/gosnmp`.

* [CHANGE] Update project path #257
* [ENHANCEMENT] Improve SNMPv3 trap support #253

## v1.27.0

* fix a race condition - logger
* INFORM responses
* linting

## v1.26.0

* more SNMPv3
* various bug fixes
* linting

## v1.25.0

* SNMPv3 new hash functions for SNMPV3 USM RFC7860
* SNMPv3 tests for SNMPv3 traps
* go versions 1.12 1.13

## v1.24.0

* doco, fix AUTHORS, fix copyright
* decode more packet types
* TCP trap listening

## v1.23.1

* add support for contexts
* fix panic conditions by checking for out-of-bounds reads

## v1.23.0

* BREAKING CHANGE: The mocks have been moved to `github.com/gosnmp/gosnmp/mocks`.
  If you use them, you will need to adjust your imports.
* bug fix: issue 170: No results when performing a walk starting on a leaf OID
* bug fix: issue 210: Set function fails if value is an Integer
* doco: loggingEnabled, MIB parser
* linting

## v1.22.0

* travis now failing build when goimports needs running
* gometalinter
* shell script for running local tests
* SNMPv3 - avoid crash when missing SecurityParameters
* add support for Walk and Get over TCP - RFC 3430
* SNMPv3 - allow input of private key instead of passphrase

## v1.21.0

* add netsnmp functionality "not check returned OIDs are increasing"

## v1.20.0

* convert all tags to correct semantic versioning, and remove old tags
* SNMPv1 trap IDs should be marshalInt32() not single byte
* use packetSecParams not sp secretKey in v3 isAuthentic()
* fix IPAddress marshalling in Set()

## v1.19.0

* bug fix: handle uninitialized v3 SecurityParameters in SnmpDecodePacket()
* SNMPError, Asn1BER - stringers; types on constants

## v1.18.0

* bug fix: use format flags - logPrintf() not logPrint()
* bug fix: parseObjectIdentifier() now returns []byte{0} rather than error
  when it receive zero length input
* use gomock
* start using go modules
* start a changelog
