package irc

import (
	"bytes"
	"errors"
	"strings"
)

var tagDecodeSlashMap = map[rune]rune{
	':':  ';',
	's':  ' ',
	'\\': '\\',
	'r':  '\r',
	'n':  '\n',
}

var tagEncodeMap = map[rune]string{
	';':  "\\:",
	' ':  "\\s",
	'\\': "\\\\",
	'\r': "\\r",
	'\n': "\\n",
}

var (
	// ErrZeroLengthMessage is returned when parsing if the input is
	// zero-length.
	ErrZeroLengthMessage = errors.New("irc: Cannot parse zero-length message")

	// ErrMissingDataAfterPrefix is returned when parsing if there is
	// no message data after the prefix.
	ErrMissingDataAfterPrefix = errors.New("irc: No message data after prefix")

	// ErrMissingDataAfterTags is returned when parsing if there is no
	// message data after the tags.
	ErrMissingDataAfterTags = errors.New("irc: No message data after tags")

	// ErrMissingCommand is returned when parsing if there is no
	// command in the parsed message.
	ErrMissingCommand = errors.New("irc: Missing message command")
)

// TagValue represents the value of a tag.
type TagValue string

// ParseTagValue parses a TagValue from the connection. If you need to
// set a TagValue, you probably want to just set the string itself, so
// it will be encoded properly.
func ParseTagValue(v string) TagValue {
	ret := &bytes.Buffer{}

	input := bytes.NewBufferString(v)

	for {
		c, _, err := input.ReadRune()
		if err != nil {
			break
		}

		if c == '\\' {
			c2, _, err := input.ReadRune()

			// If we got a backslash then the end of the tag value, we should
			// just ignore the backslash.
			if err != nil {
				break
			}

			if replacement, ok := tagDecodeSlashMap[c2]; ok {
				ret.WriteRune(replacement)
			} else {
				ret.WriteRune(c2)
			}
		} else {
			ret.WriteRune(c)
		}
	}

	return TagValue(ret.String())
}

// Encode converts a TagValue to the format in the connection.
func (v TagValue) Encode() string {
	ret := &bytes.Buffer{}

	for _, c := range v {
		if replacement, ok := tagEncodeMap[c]; ok {
			ret.WriteString(replacement)
		} else {
			ret.WriteRune(c)
		}
	}

	return ret.String()
}

// Tags represents the IRCv3 message tags.
type Tags map[string]TagValue

// ParseTags takes a tag string and parses it into a tag map. It will
// always return a tag map, even if there are no valid tags.
func ParseTags(line string) Tags {
	ret := Tags{}

	tags := strings.Split(line, ";")
	for _, tag := range tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) < 2 {
			ret[parts[0]] = ""
			continue
		}

		ret[parts[0]] = ParseTagValue(parts[1])
	}

	return ret
}

// GetTag is a convenience method to look up a tag in the map.
func (t Tags) GetTag(key string) (string, bool) {
	ret, ok := t[key]
	return string(ret), ok
}

// Copy will create a new copy of all IRC tags attached to this
// message.
func (t Tags) Copy() Tags {
	ret := Tags{}

	for k, v := range t {
		ret[k] = v
	}

	return ret
}

// String ensures this is stringable
func (t Tags) String() string {
	buf := &bytes.Buffer{}

	for k, v := range t {
		buf.WriteByte(';')
		buf.WriteString(k)
		if v != "" {
			buf.WriteByte('=')
			buf.WriteString(v.Encode())
		}
	}

	// We don't need the first byte because that's an extra ';'
	// character.
	buf.ReadByte()

	return buf.String()
}

// Prefix represents the prefix of a message, generally the user who sent it
type Prefix struct {
	// Name will contain the nick of who sent the message, the
	// server who sent the message, or a blank string
	Name string

	// User will either contain the user who sent the message or a blank string
	User string

	// Host will either contain the host of who sent the message or a blank string
	Host string
}

// ParsePrefix takes an identity string and parses it into an
// identity struct. It will always return an Prefix struct and never
// nil.
func ParsePrefix(line string) *Prefix {
	// Start by creating an Prefix with nothing but the host
	id := &Prefix{
		Name: line,
	}

	uh := strings.SplitN(id.Name, "@", 2)
	if len(uh) == 2 {
		id.Name, id.Host = uh[0], uh[1]
	}

	nu := strings.SplitN(id.Name, "!", 2)
	if len(nu) == 2 {
		id.Name, id.User = nu[0], nu[1]
	}

	return id
}

// Copy will create a new copy of an Prefix
func (p *Prefix) Copy() *Prefix {
	if p == nil {
		return nil
	}

	newPrefix := &Prefix{}

	*newPrefix = *p

	return newPrefix
}

// String ensures this is stringable
func (p *Prefix) String() string {
	buf := &bytes.Buffer{}
	buf.WriteString(p.Name)

	if p.User != "" {
		buf.WriteString("!")
		buf.WriteString(p.User)
	}

	if p.Host != "" {
		buf.WriteString("@")
		buf.WriteString(p.Host)
	}

	return buf.String()
}

// Message represents a line parsed from the server
type Message struct {
	// Each message can have IRCv3 tags
	Tags

	// Each message can have a Prefix
	*Prefix

	// Command is which command is being called.
	Command string

	// Params are all the arguments for the command.
	Params []string
}

// MustParseMessage calls ParseMessage and either returns the message
// or panics if an error is returned.
func MustParseMessage(line string) *Message {
	m, err := ParseMessage(line)
	if err != nil {
		panic(err.Error())
	}
	return m
}

// ParseMessage takes a message string (usually a whole line) and
// parses it into a Message struct. This will return nil in the case
// of invalid messages.
func ParseMessage(line string) (*Message, error) {
	// Trim the line and make sure we have data
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, ErrZeroLengthMessage
	}

	c := &Message{
		Tags:   Tags{},
		Prefix: &Prefix{},
	}

	if line[0] == '@' {
		loc := strings.Index(line, " ")
		if loc == -1 {
			return nil, ErrMissingDataAfterTags
		}

		c.Tags = ParseTags(line[1:loc])
		line = line[loc+1:]
	}

	if line[0] == ':' {
		loc := strings.Index(line, " ")
		if loc == -1 {
			return nil, ErrMissingDataAfterPrefix
		}

		// Parse the identity, if there was one
		c.Prefix = ParsePrefix(line[1:loc])
		line = line[loc+1:]
	}

	// Split out the trailing then the rest of the args. Because
	// we expect there to be at least one result as an arg (the
	// command) we don't need to special case the trailing arg and
	// can just attempt a split on " :"
	split := strings.SplitN(line, " :", 2)
	c.Params = strings.FieldsFunc(split[0], func(r rune) bool {
		return r == ' '
	})

	// If there are no args, we need to bail because we need at
	// least the command.
	if len(c.Params) == 0 {
		return nil, ErrMissingCommand
	}

	// If we had a trailing arg, append it to the other args
	if len(split) == 2 {
		c.Params = append(c.Params, split[1])
	}

	// Because of how it's parsed, the Command will show up as the
	// first arg.
	c.Command = strings.ToUpper(c.Params[0])
	c.Params = c.Params[1:]

	// If there are no params, set it to nil, to make writing tests and other
	// things simpler.
	if len(c.Params) == 0 {
		c.Params = nil
	}

	return c, nil
}

// Param returns the i'th argument in the Message or an empty string
// if the requested arg does not exist
func (m *Message) Param(i int) string {
	if i < 0 || i >= len(m.Params) {
		return ""
	}
	return m.Params[i]
}

// Trailing returns the last argument in the Message or an empty string
// if there are no args
func (m *Message) Trailing() string {
	if len(m.Params) < 1 {
		return ""
	}

	return m.Params[len(m.Params)-1]
}

// Copy will create a new copy of an message
func (m *Message) Copy() *Message {
	// Create a new message
	newMessage := &Message{}

	// Copy stuff from the old message
	*newMessage = *m

	// Copy any IRcv3 tags
	newMessage.Tags = m.Tags.Copy()

	// Copy the Prefix
	newMessage.Prefix = m.Prefix.Copy()

	// Copy the Params slice
	newMessage.Params = append(make([]string, 0, len(m.Params)), m.Params...)

	// Similar to parsing, if Params is empty, set it to nil
	if len(newMessage.Params) == 0 {
		newMessage.Params = nil
	}

	return newMessage
}

// String ensures this is stringable
func (m *Message) String() string {
	buf := &bytes.Buffer{}

	// Write any IRCv3 tags if they exist in the message
	if len(m.Tags) > 0 {
		buf.WriteByte('@')
		buf.WriteString(m.Tags.String())
		buf.WriteByte(' ')
	}

	// Add the prefix if we have one
	if m.Prefix != nil && m.Prefix.Name != "" {
		buf.WriteByte(':')
		buf.WriteString(m.Prefix.String())
		buf.WriteByte(' ')
	}

	// Add the command since we know we'll always have one
	buf.WriteString(m.Command)

	if len(m.Params) > 0 {
		args := m.Params[:len(m.Params)-1]
		trailing := m.Params[len(m.Params)-1]

		if len(args) > 0 {
			buf.WriteByte(' ')
			buf.WriteString(strings.Join(args, " "))
		}

		// If trailing is zero-length, contains a space or starts with
		// a : we need to actually specify that it's trailing.
		if len(trailing) == 0 || strings.ContainsRune(trailing, ' ') || trailing[0] == ':' {
			buf.WriteString(" :")
		} else {
			buf.WriteString(" ")
		}
		buf.WriteString(trailing)
	}

	return buf.String()
}
