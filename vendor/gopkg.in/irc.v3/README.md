# go-irc

[![GoDoc](https://img.shields.io/badge/doc-GoDoc-blue.svg)](https://godoc.org/github.com/go-irc/irc)
[![Build Status](https://img.shields.io/github/workflow/status/go-irc/irc/CI.svg)](https://github.com/go-irc/irc/actions)
[![Coverage Status](https://img.shields.io/coveralls/go-irc/irc.svg)](https://coveralls.io/github/go-irc/irc?branch=master)

This package was originally created to only handle message parsing,
but has since been expanded to include a small abstraction around a
connection and a simple client.

This library is not designed to hide any of the IRC elements from
you. If you just want to build a simple chat bot and don't want to
deal with IRC in particular, there are a number of other libraries
which provide a more full featured client if that's what you're
looking for.

This library is meant to stay as simple as possible so it can be a
building block for other packages.

This library aims for API compatibility whenever possible. New
functions and other additions will most likely not result in a major
version increase unless they break the API. This library aims to
follow the semver recommendations mentioned on gopkg.in.

Due to complications in how to support x/net/context vs the built-in context
package, only go 1.7+ is officially supported.

## Import Paths

All development happens on the `master` branch and when features are
considered stable enough, a new release will be tagged.

* `gopkg.in/irc.v3` should be used to develop against the commits
  tagged as stable
* In previous versions, `github.com/go-irc/irc` used to be able to be
  used to develop against the master branch but module support in go
  seems to have broken this.

## Development

In order to run the tests, make sure all submodules are up to date. If you are
just using this library, these are not needed.

## Example

```go
package main

import (
	"log"
	"net"

	"gopkg.in/irc.v3"
)

func main() {
	conn, err := net.Dial("tcp", "chat.freenode.net:6667")
	if err != nil {
		log.Fatalln(err)
	}

	config := irc.ClientConfig{
		Nick: "i_have_a_nick",
		Pass: "password",
		User: "username",
		Name: "Full Name",
		Handler: irc.HandlerFunc(func(c *irc.Client, m *irc.Message) {
			if m.Command == "001" {
				// 001 is a welcome event, so we join channels there
				c.Write("JOIN #bot-test-chan")
			} else if m.Command == "PRIVMSG" && c.FromChannel(m) {
				// Create a handler on all messages.
				c.WriteMessage(&irc.Message{
					Command: "PRIVMSG",
					Params: []string{
						m.Params[0],
						m.Trailing(),
					},
				})
			}
		}),
	}

	// Create the client
	client := irc.NewClient(conn, config)
	err = client.Run()
	if err != nil {
		log.Fatalln(err)
	}
}
```

## Major Version Changes

### v1

Initial release

### v2

- CTCP messages will no longer be rewritten. The decision was made that this
  library should pass through all messages without mangling them.
- Remove Message.FromChannel as this is not always accurate, while
  Client.FromChannel should always be accurate.

### v3

- Import path changed back to `gopkg.in/irc.v3` without the version suffix.
