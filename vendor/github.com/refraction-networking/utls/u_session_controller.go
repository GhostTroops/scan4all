package tls

import (
	"errors"
	"fmt"
)

// Tracking the state of calling conn.loadSession
type LoadSessionTrackerState int

const NeverCalled LoadSessionTrackerState = 0
const UtlsAboutToCall LoadSessionTrackerState = 1
const CalledByULoadSession LoadSessionTrackerState = 2
const CalledByGoTLS LoadSessionTrackerState = 3

// The state of the session controller
type sessionControllerState int

const NoSession sessionControllerState = 0
const SessionTicketExtInitialized sessionControllerState = 1
const SessionTicketExtAllSet sessionControllerState = 2
const PskExtInitialized sessionControllerState = 3
const PskExtAllSet sessionControllerState = 4

// sessionController is responsible for managing and controlling all session related states. It manages the lifecycle of the session ticket extension and the psk extension, including initialization, removal if the client hello spec doesn't contain any of them, and setting the prepared state to the client hello.
//
// Users should never directly modify the underlying state. Violations will result in undefined behaviors.
//
// Users should never construct sessionController by themselves, use the function `newSessionController` instead.
type sessionController struct {
	// sessionTicketExt logically owns the session ticket extension
	sessionTicketExt ISessionTicketExtension

	// pskExtension logically owns the psk extension
	pskExtension PreSharedKeyExtension

	// uconnRef is a reference to the uconn
	uconnRef *UConn

	// state represents the internal state of the sessionController. Users are advised to modify the state only through designated methods and avoid direct manipulation, as doing so may result in undefined behavior.
	state sessionControllerState

	// loadSessionTracker keeps track of how the conn.loadSession method is being utilized.
	loadSessionTracker LoadSessionTrackerState

	// callingLoadSession is a boolean flag that indicates whether the `conn.loadSession` function is currently being invoked.
	callingLoadSession bool

	// locked is a boolean flag that becomes true once all states are appropriately set. Once `locked` is true, further modifications are disallowed, except for the binders.
	locked bool
}

// newSessionController constructs a new SessionController
func newSessionController(uconn *UConn) *sessionController {
	return &sessionController{
		uconnRef:           uconn,
		sessionTicketExt:   &SessionTicketExtension{},
		pskExtension:       &UtlsPreSharedKeyExtension{},
		state:              NoSession,
		locked:             false,
		callingLoadSession: false,
		loadSessionTracker: NeverCalled,
	}
}

func (s *sessionController) isSessionLocked() bool {
	return s.locked
}

type shouldLoadSessionResult int

const shouldReturn shouldLoadSessionResult = 0
const shouldSetTicket shouldLoadSessionResult = 1
const shouldSetPsk shouldLoadSessionResult = 2
const shouldLoad shouldLoadSessionResult = 3

// shouldLoadSession determines the appropriate action to take when it is time to load the session for the clientHello.
// There are several possible scenarios:
//   - If a session ticket is already initialized, typically via the `initSessionTicketExt()` function, the ticket should be set in the client hello.
//   - If a pre-shared key (PSK) is already initialized, typically via the `overridePskExt()` function, the PSK should be set in the client hello.
//   - If both the `sessionTicketExt` and `pskExtension` are nil, which might occur if the client hello spec does not include them, we should skip the loadSession().
//   - In all other cases, the function proceeds to load the session.
func (s *sessionController) shouldLoadSession() shouldLoadSessionResult {
	if s.sessionTicketExt == nil && s.pskExtension == nil || s.uconnRef.clientHelloBuildStatus != NotBuilt {
		// No need to load session since we don't have the related extensions.
		return shouldReturn
	}
	if s.state == SessionTicketExtInitialized {
		return shouldSetTicket
	}
	if s.state == PskExtInitialized {
		return shouldSetPsk
	}
	return shouldLoad
}

// utlsAboutToLoadSession updates the loadSessionTracker to `UtlsAboutToCall` to signal the initiation of a session loading operation,
// provided that the preconditions are met. If the preconditions are not met (due to incorrect utls implementation), this function triggers a panic.
func (s *sessionController) utlsAboutToLoadSession() {
	uAssert(s.state == NoSession && !s.locked, "tls: aboutToLoadSession failed: must only load session when the session of the client hello is not locked and when there's currently no session")
	s.loadSessionTracker = UtlsAboutToCall
}

func (s *sessionController) assertHelloNotBuilt(caller string) {
	if s.uconnRef.clientHelloBuildStatus != NotBuilt {
		panic(fmt.Sprintf("tls: %s failed: we can't modify the session after the clientHello is built", caller))
	}
}

func (s *sessionController) assertControllerState(caller string, desired sessionControllerState, moreDesiredStates ...sessionControllerState) {
	if s.state != desired && !anyTrue(moreDesiredStates, func(_ int, state *sessionControllerState) bool {
		return s.state == *state
	}) {
		panic(fmt.Sprintf("tls: %s failed: undesired controller state %d", caller, s.state))
	}
}

func (s *sessionController) assertNotLocked(caller string) {
	if s.locked {
		panic(fmt.Sprintf("tls: %s failed: you must not modify the session after it's locked", caller))
	}
}

// finalCheck performs a comprehensive check on the updated state to ensure the correctness of the changes.
// If the checks pass successfully, the sessionController's state will be locked.
// Any failure in passing the tests indicates incorrect implementations in the utls, which will result in triggering a panic.
// Refer to the documentation for the `locked` field for more detailed information.
func (s *sessionController) finalCheck() {
	s.assertControllerState("SessionController.finalCheck", PskExtAllSet, SessionTicketExtAllSet, NoSession)
	s.locked = true
}

func initializationGuard[E Initializable, I func(E)](extension E, initializer I) {
	uAssert(!extension.IsInitialized(), "tls: initialization failed: the extension is already initialized")
	initializer(extension)
	uAssert(extension.IsInitialized(), "tls: initialization failed: the extension is not initialized after initialization")
}

// initSessionTicketExt initializes the ticket and sets the state to `TicketInitialized`.
func (s *sessionController) initSessionTicketExt(session *SessionState, ticket []byte) {
	s.assertNotLocked("initSessionTicketExt")
	s.assertHelloNotBuilt("initSessionTicketExt")
	s.assertControllerState("initSessionTicketExt", NoSession)
	panicOnNil("initSessionTicketExt", s.sessionTicketExt, session, ticket)
	initializationGuard(s.sessionTicketExt, func(e ISessionTicketExtension) {
		s.sessionTicketExt.InitializeByUtls(session, ticket)
	})
	s.state = SessionTicketExtInitialized
}

// initPSK initializes the PSK extension using a valid session. The PSK extension
// should not be initialized previously, and the parameters must not be nil;
// otherwise, this function will trigger a panic.
func (s *sessionController) initPskExt(session *SessionState, earlySecret []byte, binderKey []byte, pskIdentities []pskIdentity) {
	s.assertNotLocked("initPskExt")
	s.assertHelloNotBuilt("initPskExt")
	s.assertControllerState("initPskExt", NoSession)
	panicOnNil("initPskExt", s.pskExtension, session, earlySecret, pskIdentities)

	initializationGuard(s.pskExtension, func(e PreSharedKeyExtension) {
		publicPskIdentities := mapSlice(pskIdentities, func(private pskIdentity) PskIdentity {
			return PskIdentity{
				Label:               private.label,
				ObfuscatedTicketAge: private.obfuscatedTicketAge,
			}
		})
		e.InitializeByUtls(session, earlySecret, binderKey, publicPskIdentities)
	})

	s.state = PskExtInitialized
}

// setSessionTicketToUConn write the ticket states from the session ticket extension to the client hello and handshake state.
func (s *sessionController) setSessionTicketToUConn() {
	uAssert(s.sessionTicketExt != nil && s.state == SessionTicketExtInitialized, "tls: setSessionTicketExt failed: invalid state")
	s.uconnRef.HandshakeState.Session = s.sessionTicketExt.GetSession()
	s.uconnRef.HandshakeState.Hello.SessionTicket = s.sessionTicketExt.GetTicket()
	s.state = SessionTicketExtAllSet
}

// setPskToUConn sets the psk to the handshake state and client hello.
func (s *sessionController) setPskToUConn() {
	uAssert(s.pskExtension != nil && (s.state == PskExtInitialized || s.state == PskExtAllSet), "tls: setPskToUConn failed: invalid state")
	pskCommon := s.pskExtension.GetPreSharedKeyCommon()
	if s.state == PskExtInitialized {
		s.uconnRef.HandshakeState.State13.EarlySecret = pskCommon.EarlySecret
		s.uconnRef.HandshakeState.Session = pskCommon.Session
		s.uconnRef.HandshakeState.Hello.PskIdentities = pskCommon.Identities
		s.uconnRef.HandshakeState.Hello.PskBinders = pskCommon.Binders
	} else if s.state == PskExtAllSet {
		uAssert(s.uconnRef.HandshakeState.Session == pskCommon.Session && sliceEq(s.uconnRef.HandshakeState.State13.EarlySecret, pskCommon.EarlySecret) &&
			allTrue(s.uconnRef.HandshakeState.Hello.PskIdentities, func(i int, psk *PskIdentity) bool {
				return pskCommon.Identities[i].ObfuscatedTicketAge == psk.ObfuscatedTicketAge && sliceEq(pskCommon.Identities[i].Label, psk.Label)
			}), "tls: setPskToUConn failed: only binders are allowed to change on state `PskAllSet`")
	}
	s.uconnRef.HandshakeState.State13.BinderKey = pskCommon.BinderKey
	s.state = PskExtAllSet
}

// shouldUpdateBinders determines whether binders should be updated based on the presence of an initialized psk extension.
// This function returns true if an initialized psk extension exists. Binders are allowed to be updated when the state is `PskAllSet`,
// as the `BuildHandshakeState` function can be called multiple times in this case. However, it's important to note that
// the session state, apart from binders, should not be altered more than once.
func (s *sessionController) shouldUpdateBinders() bool {
	if s.pskExtension == nil {
		return false
	}
	return (s.state == PskExtInitialized || s.state == PskExtAllSet)
}

func (s *sessionController) updateBinders() {
	uAssert(s.shouldUpdateBinders(), "tls: updateBinders failed: shouldn't update binders")
	s.pskExtension.PatchBuiltHello(s.uconnRef.HandshakeState.Hello)
}

func (s *sessionController) overrideExtension(extension Initializable, override func(), initializedState sessionControllerState) error {
	panicOnNil("overrideExtension", extension)
	s.assertNotLocked("overrideExtension")
	s.assertControllerState("overrideExtension", NoSession)
	override()
	if extension.IsInitialized() {
		s.state = initializedState
	}
	return nil
}

// overridePskExt allows the user of utls to customize the psk extension.
func (s *sessionController) overridePskExt(pskExt PreSharedKeyExtension) error {
	return s.overrideExtension(pskExt, func() { s.pskExtension = pskExt }, PskExtInitialized)
}

// overridePskExt allows the user of utls to customize the session ticket extension.
func (s *sessionController) overrideSessionTicketExt(sessionTicketExt ISessionTicketExtension) error {
	return s.overrideExtension(sessionTicketExt, func() { s.sessionTicketExt = sessionTicketExt }, SessionTicketExtInitialized)
}

// syncSessionExts synchronizes the sessionController with the session-related
// extensions from the extension list after applying client hello specs.
//
//   - If the extension list is missing the session ticket extension or PSK
//     extension, owned extensions are dropped and states are reset.
//   - If the user provides a session ticket extension or PSK extension, the
//     corresponding extension from the extension list will be replaced.
//   - If the user doesn't provide session-related extensions, the extensions
//     from the extension list will be utilized.
//
// This function ensures that there is only one session ticket extension or PSK
// extension, and that the PSK extension is the last extension in the extension
// list.
func (s *sessionController) syncSessionExts() error {
	uAssert(s.uconnRef.clientHelloBuildStatus == NotBuilt, "tls: checkSessionExts failed: we can't modify the session after the clientHello is built")
	s.assertNotLocked("checkSessionExts")
	s.assertHelloNotBuilt("checkSessionExts")
	s.assertControllerState("checkSessionExts", NoSession, SessionTicketExtInitialized, PskExtInitialized)
	numSessionExt := 0
	hasPskExt := false
	for i, e := range s.uconnRef.Extensions {
		switch ext := e.(type) {
		case ISessionTicketExtension:
			uAssert(numSessionExt == 0, "tls: checkSessionExts failed: multiple ISessionTicketExtensions in the extension list")
			if s.sessionTicketExt == nil {
				// If there isn't a user-provided session ticket extension, use the one from the spec
				s.sessionTicketExt = ext
			} else {
				// Otherwise, replace the one in the extension list with the user-provided one
				s.uconnRef.Extensions[i] = s.sessionTicketExt
			}
			numSessionExt += 1
		case PreSharedKeyExtension:
			uAssert(i == len(s.uconnRef.Extensions)-1, "tls: checkSessionExts failed: PreSharedKeyExtension must be the last extension")
			if s.pskExtension == nil {
				// If there isn't a user-provided psk extension, use the one from the spec
				s.pskExtension = ext
			} else {
				// Otherwise, replace the one in the extension list with the user-provided one
				s.uconnRef.Extensions[i] = s.pskExtension
			}
			s.pskExtension.SetOmitEmptyPsk(s.uconnRef.config.OmitEmptyPsk)
			hasPskExt = true
		}
	}
	if numSessionExt == 0 {
		if s.state == SessionTicketExtInitialized {
			return errors.New("tls: checkSessionExts failed: the user provided a session ticket, but the specification doesn't contain one")
		}
		s.sessionTicketExt = nil
		s.uconnRef.HandshakeState.Session = nil
		s.uconnRef.HandshakeState.Hello.SessionTicket = nil
	}
	if !hasPskExt {
		if s.state == PskExtInitialized {
			return errors.New("tls: checkSessionExts failed: the user provided a psk, but the specification doesn't contain one")
		}
		s.pskExtension = nil
		s.uconnRef.HandshakeState.State13.BinderKey = nil
		s.uconnRef.HandshakeState.State13.EarlySecret = nil
		s.uconnRef.HandshakeState.Session = nil
		s.uconnRef.HandshakeState.Hello.PskIdentities = nil
	}
	return nil
}

// onEnterLoadSessionCheck is intended to be invoked upon entering the `conn.loadSession` function.
// It is designed to ensure the correctness of the utls implementation. If the utls implementation is found to be incorrect, this function will trigger a panic.
func (s *sessionController) onEnterLoadSessionCheck() {
	uAssert(!s.locked, "tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: session is set and locked, no call to loadSession is allowed")
	switch s.loadSessionTracker {
	case UtlsAboutToCall, NeverCalled:
		s.callingLoadSession = true
	case CalledByULoadSession, CalledByGoTLS:
		panic("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: you must not call loadSession() twice")
	default:
		panic("tls: LoadSessionCoordinator.onEnterLoadSessionCheck failed: unimplemented state")
	}
}

// onLoadSessionReturn is intended to be invoked upon returning from the `conn.loadSession` function.
// It serves as a validation step for the correctness of the underlying utls implementation.
// If the utls implementation is incorrect, this function will trigger a panic.
func (s *sessionController) onLoadSessionReturn() {
	uAssert(s.callingLoadSession, "tls: LoadSessionCoordinator.onLoadSessionReturn failed: it's not loading sessions, perhaps this function is not being called by loadSession.")
	switch s.loadSessionTracker {
	case NeverCalled:
		s.loadSessionTracker = CalledByGoTLS
	case UtlsAboutToCall:
		s.loadSessionTracker = CalledByULoadSession
	default:
		panic("tls: LoadSessionCoordinator.onLoadSessionReturn failed: unimplemented state")
	}
	s.callingLoadSession = false
}

// shouldLoadSessionWriteBinders checks if `conn.loadSession` should proceed to write binders and marshal the client hello. If the utls implementation
// is incorrect, this function will trigger a panic.
func (s *sessionController) shouldLoadSessionWriteBinders() bool {
	uAssert(s.callingLoadSession, "tls: shouldWriteBinders failed: LoadSessionCoordinator isn't loading sessions, perhaps this function is not being called by loadSession.")

	switch s.loadSessionTracker {
	case NeverCalled:
		return true
	case UtlsAboutToCall:
		return false
	default:
		panic("tls: shouldWriteBinders failed: unimplemented state")
	}
}
