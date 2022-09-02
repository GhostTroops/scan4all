package engine

import (
	"context"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/rod/lib/utils"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/segmentio/ksuid"
)

var (
	invalidArgumentsError = errors.New("invalid arguments provided")
)

const (
	couldNotGetElementErrorMessage = "could not get element"
	couldNotScrollErrorMessage     = "could not scroll into view"
)

// ExecuteActions executes a list of actions on a page.
func (p *Page) ExecuteActions(baseURL *url.URL, actions []*Action) (map[string]string, error) {
	var err error

	outData := make(map[string]string)
	for _, act := range actions {
		switch act.ActionType.ActionType {
		case ActionNavigate:
			err = p.NavigateURL(act, outData, baseURL)
		case ActionScript:
			err = p.RunScript(act, outData)
		case ActionClick:
			err = p.ClickElement(act, outData)
		case ActionRightClick:
			err = p.RightClickElement(act, outData)
		case ActionTextInput:
			err = p.InputElement(act, outData)
		case ActionScreenshot:
			err = p.Screenshot(act, outData)
		case ActionTimeInput:
			err = p.TimeInputElement(act, outData)
		case ActionSelectInput:
			err = p.SelectInputElement(act, outData)
		case ActionWaitLoad:
			err = p.WaitLoad(act, outData)
		case ActionGetResource:
			err = p.GetResource(act, outData)
		case ActionExtract:
			err = p.ExtractElement(act, outData)
		case ActionWaitEvent:
			err = p.WaitEvent(act, outData)
		case ActionFilesInput:
			err = p.FilesInput(act, outData)
		case ActionAddHeader:
			err = p.ActionAddHeader(act, outData)
		case ActionSetHeader:
			err = p.ActionSetHeader(act, outData)
		case ActionDeleteHeader:
			err = p.ActionDeleteHeader(act, outData)
		case ActionSetBody:
			err = p.ActionSetBody(act, outData)
		case ActionSetMethod:
			err = p.ActionSetMethod(act, outData)
		case ActionKeyboard:
			err = p.KeyboardAction(act, outData)
		case ActionDebug:
			err = p.DebugAction(act, outData)
		case ActionSleep:
			err = p.SleepAction(act, outData)
		case ActionWaitVisible:
			err = p.WaitVisible(act, outData)
		default:
			continue
		}
		if err != nil {
			return nil, errors.Wrap(err, "error occurred executing action")
		}
	}
	return outData, nil
}

type requestRule struct {
	Action ActionType
	Part   string
	Args   map[string]string
}

const elementDidNotAppearMessage = "Element did not appear in the given amount of time"

// WaitVisible waits until an element appears.
func (p *Page) WaitVisible(act *Action, out map[string]string) error {
	timeout, err := getTimeout(p, act)
	if err != nil {
		return errors.Wrap(err, "Wrong timeout given")
	}

	pollTime, err := getPollTime(p, act)
	if err != nil {
		return errors.Wrap(err, "Wrong polling time given")
	}

	element, _ := p.Sleeper(pollTime, timeout).
		Timeout(timeout).
		pageElementBy(act.Data)

	if element != nil {
		if err := element.WaitVisible(); err != nil {
			return errors.Wrap(err, elementDidNotAppearMessage)
		}
	} else {
		return errors.New(elementDidNotAppearMessage)
	}

	return nil
}

func (p *Page) Sleeper(pollTimeout, timeout time.Duration) *Page {
	page := *p
	page.page = page.Page().Sleeper(func() utils.Sleeper {
		return createBackOffSleeper(pollTimeout, timeout)
	})
	return &page
}

func (p *Page) Timeout(timeout time.Duration) *Page {
	page := *p
	page.page = page.Page().Timeout(timeout)
	return &page
}

func createBackOffSleeper(pollTimeout, timeout time.Duration) utils.Sleeper {
	backoffSleeper := utils.BackoffSleeper(pollTimeout, timeout, func(duration time.Duration) time.Duration {
		return duration
	})

	return func(ctx context.Context) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		return backoffSleeper(ctx)
	}
}

func getTimeout(p *Page, act *Action) (time.Duration, error) {
	return geTimeParameter(p, act, "timeout", 3, time.Second)
}

func getPollTime(p *Page, act *Action) (time.Duration, error) {
	return geTimeParameter(p, act, "pollTime", 100, time.Millisecond)
}

func geTimeParameter(p *Page, act *Action, parameterName string, defaultValue time.Duration, duration time.Duration) (time.Duration, error) {
	pollTimeString := p.getActionArgWithDefaultValues(act, parameterName)
	if pollTimeString == "" {
		return defaultValue * duration, nil
	}
	timeout, err := strconv.Atoi(pollTimeString)
	if err != nil {
		return time.Duration(0), err
	}
	return time.Duration(timeout) * duration, nil
}

// ActionAddHeader executes a AddHeader action.
func (p *Page) ActionAddHeader(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["key"] = p.getActionArgWithDefaultValues(act, "key")
	args["value"] = p.getActionArgWithDefaultValues(act, "value")
	rule := requestRule{
		Action: ActionAddHeader,
		Part:   in,
		Args:   args,
	}
	p.rules = append(p.rules, rule)
	return nil
}

// ActionSetHeader executes a SetHeader action.
func (p *Page) ActionSetHeader(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["key"] = p.getActionArgWithDefaultValues(act, "key")
	args["value"] = p.getActionArgWithDefaultValues(act, "value")
	rule := requestRule{
		Action: ActionSetHeader,
		Part:   in,
		Args:   args,
	}
	p.rules = append(p.rules, rule)
	return nil
}

// ActionDeleteHeader executes a DeleteHeader action.
func (p *Page) ActionDeleteHeader(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["key"] = p.getActionArgWithDefaultValues(act, "key")
	rule := requestRule{
		Action: ActionDeleteHeader,
		Part:   in,
		Args:   args,
	}
	p.rules = append(p.rules, rule)
	return nil
}

// ActionSetBody executes a SetBody action.
func (p *Page) ActionSetBody(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["body"] = p.getActionArgWithDefaultValues(act, "body")
	rule := requestRule{
		Action: ActionSetBody,
		Part:   in,
		Args:   args,
	}
	p.rules = append(p.rules, rule)
	return nil
}

// ActionSetMethod executes an SetMethod action.
func (p *Page) ActionSetMethod(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	in := p.getActionArgWithDefaultValues(act, "part")

	args := make(map[string]string)
	args["method"] = p.getActionArgWithDefaultValues(act, "method")
	rule := requestRule{
		Action: ActionSetMethod,
		Part:   in,
		Args:   args,
	}
	p.rules = append(p.rules, rule)
	return nil
}

// NavigateURL executes an ActionLoadURL actions loading a URL for the page.
func (p *Page) NavigateURL(action *Action, out map[string]string, parsed *url.URL /*TODO review unused parameter*/) error {
	URL := p.getActionArgWithDefaultValues(action, "url")
	if URL == "" {
		return invalidArgumentsError
	}

	// Handle the dynamic value substitution here.
	URL, parsed = baseURLWithTemplatePrefs(URL, parsed)
	if strings.HasSuffix(parsed.Path, "/") && strings.Contains(URL, "{{BaseURL}}/") {
		parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	}
	parsedString := parsed.String()
	final := replaceWithValues(URL, map[string]interface{}{
		"Hostname": parsed.Hostname(),
		"BaseURL":  parsedString,
	})

	if err := p.page.Navigate(final); err != nil {
		return errors.Wrap(err, "could not navigate")
	}
	return nil
}

// RunScript runs a script on the loaded page
func (p *Page) RunScript(action *Action, out map[string]string) error {
	code := p.getActionArgWithDefaultValues(action, "code")
	if code == "" {
		return invalidArgumentsError
	}
	if p.getActionArgWithDefaultValues(action, "hook") == "true" {
		if _, err := p.page.EvalOnNewDocument(code); err != nil {
			return err
		}
	}
	data, err := p.page.Eval(code)
	if err != nil {
		return err
	}
	if data != nil && action.Name != "" {
		out[action.Name] = data.Value.String()
	}
	return nil
}

// ClickElement executes click actions for an element.
func (p *Page) ClickElement(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}
	if err = element.Click(proto.InputMouseButtonLeft); err != nil {
		return errors.Wrap(err, "could not click element")
	}
	return nil
}

// KeyboardAction executes a keyboard action on the page.
func (p *Page) KeyboardAction(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	return p.page.Keyboard.Type([]input.Key(p.getActionArgWithDefaultValues(act, "keys"))...)
}

// RightClickElement executes right click actions for an element.
func (p *Page) RightClickElement(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}
	if err = element.Click(proto.InputMouseButtonRight); err != nil {
		return errors.Wrap(err, "could not right click element")
	}
	return nil
}

// Screenshot executes screenshot action on a page
func (p *Page) Screenshot(act *Action, out map[string]string) error {
	to := p.getActionArgWithDefaultValues(act, "to")
	if to == "" {
		to = ksuid.New().String()
		if act.Name != "" {
			out[act.Name] = to
		}
	}
	var data []byte
	var err error
	if p.getActionArgWithDefaultValues(act, "fullpage") == "true" {
		data, err = p.page.Screenshot(true, &proto.PageCaptureScreenshot{})
	} else {
		data, err = p.page.Screenshot(false, &proto.PageCaptureScreenshot{})
	}
	if err != nil {
		return errors.Wrap(err, "could not take screenshot")
	}
	err = os.WriteFile(to+".png", data, 0540)
	if err != nil {
		return errors.Wrap(err, "could not write screenshot")
	}
	return nil
}

// InputElement executes input element actions for an element.
func (p *Page) InputElement(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	value := p.getActionArgWithDefaultValues(act, "value")
	if value == "" {
		return invalidArgumentsError
	}
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}
	if err = element.Input(value); err != nil {
		return errors.Wrap(err, "could not input element")
	}
	return nil
}

// TimeInputElement executes time input on an element
func (p *Page) TimeInputElement(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	value := p.getActionArgWithDefaultValues(act, "value")
	if value == "" {
		return invalidArgumentsError
	}
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return errors.Wrap(err, "could not parse time")
	}
	if err := element.InputTime(t); err != nil {
		return errors.Wrap(err, "could not input element")
	}
	return nil
}

// SelectInputElement executes select input statement action on a element
func (p *Page) SelectInputElement(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	value := p.getActionArgWithDefaultValues(act, "value")
	if value == "" {
		return invalidArgumentsError
	}
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}

	selectedBool := false
	if p.getActionArgWithDefaultValues(act, "selected") == "true" {
		selectedBool = true
	}
	by := p.getActionArgWithDefaultValues(act, "selector")
	if err := element.Select([]string{value}, selectedBool, selectorBy(by)); err != nil {
		return errors.Wrap(err, "could not select input")
	}
	return nil
}

// WaitLoad waits for the page to load
func (p *Page) WaitLoad(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	p.page.Timeout(2 * time.Second).WaitNavigation(proto.PageLifecycleEventNameDOMContentLoaded)()

	// Wait for the window.onload event and also wait for the network requests
	// to become idle for a maximum duration of 3 seconds. If the requests
	// do not finish,
	if err := p.page.WaitLoad(); err != nil {
		return errors.Wrap(err, "could not wait load event")
	}
	_ = p.page.WaitIdle(1 * time.Second)
	return nil
}

// GetResource gets a resource from an element from page.
func (p *Page) GetResource(act *Action, out map[string]string) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	resource, err := element.Resource()
	if err != nil {
		return errors.Wrap(err, "could not get src for element")
	}
	if act.Name != "" {
		out[act.Name] = string(resource)
	}
	return nil
}

// FilesInput acts with a file input element on page
func (p *Page) FilesInput(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}
	value := p.getActionArgWithDefaultValues(act, "value")
	filesPaths := strings.Split(value, ",")
	if err := element.SetFiles(filesPaths); err != nil {
		return errors.Wrap(err, "could not set files")
	}
	return nil
}

// ExtractElement extracts from an element on the page.
func (p *Page) ExtractElement(act *Action, out map[string]string) error {
	element, err := p.pageElementBy(act.Data)
	if err != nil {
		return errors.Wrap(err, couldNotGetElementErrorMessage)
	}
	if err = element.ScrollIntoView(); err != nil {
		return errors.Wrap(err, couldNotScrollErrorMessage)
	}
	switch p.getActionArgWithDefaultValues(act, "target") {
	case "attribute":
		attrName := p.getActionArgWithDefaultValues(act, "attribute")
		if attrName == "" {
			return errors.New("attribute can't be empty")
		}
		attrValue, err := element.Attribute(attrName)
		if err != nil {
			return errors.Wrap(err, "could not get attribute")
		}
		if act.Name != "" {
			out[act.Name] = *attrValue
		}
	default:
		text, err := element.Text()
		if err != nil {
			return errors.Wrap(err, "could not get element text node")
		}
		if act.Name != "" {
			out[act.Name] = text
		}
	}
	return nil
}

type protoEvent struct {
	event string
}

// ProtoEvent returns the cdp.Event.Method
func (p *protoEvent) ProtoEvent() string {
	return p.event
}

// WaitEvent waits for an event to happen on the page.
func (p *Page) WaitEvent(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	event := p.getActionArgWithDefaultValues(act, "event")
	if event == "" {
		return errors.New("event not recognized")
	}
	protoEvent := &protoEvent{event: event}

	// Uses another instance in order to be able to chain the timeout only to the wait operation
	pageCopy := p.page
	timeout := p.getActionArg(act, "timeout")
	if timeout != "" {
		ts, err := strconv.Atoi(timeout)
		if err != nil {
			return errors.Wrap(err, "could not get timeout")
		}
		if ts > 0 {
			pageCopy = p.page.Timeout(time.Duration(ts) * time.Second)
		}
	}
	// Just wait the event to happen
	pageCopy.WaitEvent(protoEvent)()
	return nil
}

// pageElementBy returns a page element from a variety of inputs.
//
// Supported values for by: r -> selector & regex, x -> xpath, js -> eval js,
// search => query, default ("") => selector.
func (p *Page) pageElementBy(data map[string]string) (*rod.Element, error) {
	by, ok := data["by"]
	if !ok {
		by = ""
	}
	page := p.page

	switch by {
	case "r", "regex":
		return page.ElementR(data["selector"], data["regex"])
	case "x", "xpath":
		return page.ElementX(data["xpath"])
	case "js":
		return page.ElementByJS(&rod.EvalOptions{JS: data["js"]})
	case "search":
		elms, err := page.Search(data["query"])
		if err != nil {
			return nil, err
		}

		if elms.First != nil {
			return elms.First, nil
		}
		return nil, errors.New("no such element")
	default:
		return page.Element(data["selector"])
	}
}

// DebugAction enables debug action on a page.
func (p *Page) DebugAction(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	p.instance.browser.engine.SlowMotion(5 * time.Second)
	p.instance.browser.engine.Trace(true)
	return nil
}

// SleepAction sleeps on the page for a specified duration
func (p *Page) SleepAction(act *Action, out map[string]string /*TODO review unused parameter*/) error {
	seconds := act.Data["duration"]
	if seconds == "" {
		seconds = "5"
	}
	parsed, err := strconv.Atoi(seconds)
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(parsed) * time.Second)
	return nil
}

// selectorBy returns a selector from a representation.
func selectorBy(selector string) rod.SelectorType {
	switch selector {
	case "r":
		return rod.SelectorTypeRegex
	case "css":
		return rod.SelectorTypeCSSSector
	case "regex":
		return rod.SelectorTypeRegex
	default:
		return rod.SelectorTypeText
	}
}

var (
	urlWithPortRegex = regexp.MustCompile(`{{BaseURL}}:(\d+)`)
)

// baseURLWithTemplatePrefs returns the url for BaseURL keeping
// the template port and path preference over the user provided one.
func baseURLWithTemplatePrefs(data string, parsed *url.URL) (string, *url.URL) {
	// template port preference over input URL port if template has a port
	matches := urlWithPortRegex.FindAllStringSubmatch(data, -1)
	if len(matches) == 0 {
		return data, parsed
	}
	port := matches[0][1]
	parsed.Host = net.JoinHostPort(parsed.Hostname(), port)
	data = strings.ReplaceAll(data, ":"+port, "")
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return data, parsed
}

func (p *Page) getActionArg(action *Action, arg string) string {
	return p.getActionArgWithValues(action, arg, nil)
}

func (p *Page) getActionArgWithDefaultValues(action *Action, arg string) string {
	return p.getActionArgWithValues(action, arg, generators.MergeMaps(
		generators.BuildPayloadFromOptions(p.instance.browser.options),
		p.payloads,
	))
}

func (p *Page) getActionArgWithValues(action *Action, arg string, values map[string]interface{}) string {
	argValue := action.GetArg(arg)
	argValue = replaceWithValues(argValue, values)
	if p.instance.interactsh != nil {
		var interactshURLs []string
		argValue, interactshURLs = p.instance.interactsh.ReplaceMarkers(argValue, p.InteractshURLs)
		p.addInteractshURL(interactshURLs...)
	}
	return argValue
}
