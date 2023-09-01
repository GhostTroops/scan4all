package soap

import (
	"strconv"

	"github.com/masterzen/simplexml/dom"
)

type HeaderOption struct {
	key   string
	value string
}

func NewHeaderOption(name string, value string) *HeaderOption {
	return &HeaderOption{key: name, value: value}
}

type SoapHeader struct {
	to              string
	replyTo         string
	maxEnvelopeSize string
	timeout         string
	locale          string
	id              string
	action          string
	shellID         string
	resourceURI     string
	options         []HeaderOption
	message         *SoapMessage
}

type HeaderBuilder interface {
	To(string) *SoapHeader
	ReplyTo(string) *SoapHeader
	MaxEnvelopeSize(int) *SoapHeader
	Timeout(string) *SoapHeader
	Locale(string) *SoapHeader
	Id(string) *SoapHeader
	Action(string) *SoapHeader
	ShellId(string) *SoapHeader
	resourceURI(string) *SoapHeader
	AddOption(*HeaderOption) *SoapHeader
	Options([]HeaderOption) *SoapHeader
	Build(*SoapMessage) *SoapMessage
}

func (sh *SoapHeader) To(uri string) *SoapHeader {
	sh.to = uri
	return sh
}

func (sh *SoapHeader) ReplyTo(uri string) *SoapHeader {
	sh.replyTo = uri
	return sh
}

func (sh *SoapHeader) MaxEnvelopeSize(size int) *SoapHeader {
	sh.maxEnvelopeSize = strconv.Itoa(size)
	return sh
}

func (sh *SoapHeader) Timeout(timeout string) *SoapHeader {
	sh.timeout = timeout
	return sh
}

//nolint:stylecheck // Should be ShellID, but we stay compatible
func (sh *SoapHeader) Id(id string) *SoapHeader {
	sh.id = id
	return sh
}

func (sh *SoapHeader) Action(action string) *SoapHeader {
	sh.action = action
	return sh
}

func (sh *SoapHeader) Locale(locale string) *SoapHeader {
	sh.locale = locale
	return sh
}

//nolint:stylecheck // Should be ShellID, but we stay compatible
func (sh *SoapHeader) ShellId(shellId string) *SoapHeader {
	sh.shellID = shellId
	return sh
}

func (sh *SoapHeader) ResourceURI(resourceURI string) *SoapHeader {
	sh.resourceURI = resourceURI
	return sh
}

func (sh *SoapHeader) AddOption(option *HeaderOption) *SoapHeader {
	sh.options = append(sh.options, *option)
	return sh
}

func (sh *SoapHeader) Options(options []HeaderOption) *SoapHeader {
	sh.options = options
	return sh
}

func (sh *SoapHeader) Build() *SoapMessage {
	header := sh.createElement(sh.message.envelope, "Header", DOM_NS_SOAP_ENV)

	if sh.to != "" {
		to := sh.createElement(header, "To", DOM_NS_ADDRESSING)
		to.SetContent(sh.to)
	}

	if sh.replyTo != "" {
		replyTo := sh.createElement(header, "ReplyTo", DOM_NS_ADDRESSING)
		a := sh.createMUElement(replyTo, "Address", DOM_NS_ADDRESSING, true)
		a.SetContent(sh.replyTo)
	}

	if sh.maxEnvelopeSize != "" {
		envelope := sh.createMUElement(header, "MaxEnvelopeSize", DOM_NS_WSMAN_DMTF, true)
		envelope.SetContent(sh.maxEnvelopeSize)
	}

	if sh.timeout != "" {
		timeout := sh.createElement(header, "OperationTimeout", DOM_NS_WSMAN_DMTF)
		timeout.SetContent(sh.timeout)
	}

	if sh.id != "" {
		id := sh.createElement(header, "MessageID", DOM_NS_ADDRESSING)
		id.SetContent(sh.id)
	}

	if sh.locale != "" {
		locale := sh.createMUElement(header, "Locale", DOM_NS_WSMAN_DMTF, false)
		locale.SetAttr("xml:lang", sh.locale)
		datalocale := sh.createMUElement(header, "DataLocale", DOM_NS_WSMAN_MSFT, false)
		datalocale.SetAttr("xml:lang", sh.locale)
	}

	if sh.action != "" {
		action := sh.createMUElement(header, "Action", DOM_NS_ADDRESSING, true)
		action.SetContent(sh.action)
	}

	if sh.shellID != "" {
		selectorSet := sh.createElement(header, "SelectorSet", DOM_NS_WSMAN_DMTF)
		selector := sh.createElement(selectorSet, "Selector", DOM_NS_WSMAN_DMTF)
		selector.SetAttr("Name", "ShellId")
		selector.SetContent(sh.shellID)
	}

	if sh.resourceURI != "" {
		resource := sh.createMUElement(header, "ResourceURI", DOM_NS_WSMAN_DMTF, true)
		resource.SetContent(sh.resourceURI)
	}

	if len(sh.options) > 0 {
		set := sh.createElement(header, "OptionSet", DOM_NS_WSMAN_DMTF)
		for _, option := range sh.options {
			e := sh.createElement(set, "Option", DOM_NS_WSMAN_DMTF)
			e.SetAttr("Name", option.key)
			e.SetContent(option.value)
		}
	}

	return sh.message
}

func (sh *SoapHeader) createElement(parent *dom.Element, name string, ns dom.Namespace) (element *dom.Element) {
	element = dom.CreateElement(name)
	parent.AddChild(element)
	ns.SetTo(element)
	return
}

func (sh *SoapHeader) createMUElement(parent *dom.Element, name string, ns dom.Namespace, mustUnderstand bool) (element *dom.Element) {
	element = sh.createElement(parent, name, ns)
	value := "false"
	if mustUnderstand {
		value = "true"
	}
	element.SetAttr("mustUnderstand", value)
	return
}
