package ansi

import (
	"bytes"
	"io"
	"net/url"
)

// A LinkElement is used to render hyperlinks.
type LinkElement struct {
	BaseURL  string
	URL      string
	Children []ElementRenderer
}

func (e *LinkElement) Render(w io.Writer, ctx RenderContext) error {
	for _, child := range e.Children {
		if r, ok := child.(StyleOverriderElementRenderer); ok {
			st := ctx.options.Styles.LinkText
			if err := r.StyleOverrideRender(w, ctx, st); err != nil {
				return err
			}
		} else {
			var b bytes.Buffer
			if err := child.Render(&b, ctx); err != nil {
				return err
			}
			el := &BaseElement{
				Token: b.String(),
				Style: ctx.options.Styles.LinkText,
			}
			if err := el.Render(w, ctx); err != nil {
				return err
			}
		}
	}

	u, err := url.Parse(e.URL)
	if err == nil && "#"+u.Fragment != e.URL { // if the URL only consists of an anchor, ignore it
		el := &BaseElement{
			Token:  resolveRelativeURL(e.BaseURL, e.URL),
			Prefix: " ",
			Style:  ctx.options.Styles.Link,
		}
		if err := el.Render(w, ctx); err != nil {
			return err
		}
	}

	return nil
}
