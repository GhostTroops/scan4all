xmlquery
====
[![Build Status](https://travis-ci.org/antchfx/xmlquery.svg?branch=master)](https://travis-ci.org/antchfx/xmlquery)
[![Coverage Status](https://coveralls.io/repos/github/antchfx/xmlquery/badge.svg?branch=master)](https://coveralls.io/github/antchfx/xmlquery?branch=master)
[![GoDoc](https://godoc.org/github.com/antchfx/xmlquery?status.svg)](https://godoc.org/github.com/antchfx/xmlquery)
[![Go Report Card](https://goreportcard.com/badge/github.com/antchfx/xmlquery)](https://goreportcard.com/report/github.com/antchfx/xmlquery)

Overview
===

`xmlquery` is an XPath query package for XML documents, allowing you to extract 
data or evaluate from XML documents with an XPath expression.

`xmlquery` has a built-in query object caching feature that caches recently used
XPATH query strings. Enabling caching can avoid recompile XPath expression for 
each query. 

You can visit this page to learn about the supported XPath(1.0/2.0) syntax. https://github.com/antchfx/xpath

[htmlquery](https://github.com/antchfx/htmlquery)	- Package for the HTML document query.

[xmlquery](https://github.com/antchfx/xmlquery)	- Package for the XML document query.

[jsonquery](https://github.com/antchfx/jsonquery)	- Package for the JSON document query.

Installation
====
```
 $ go get github.com/antchfx/xmlquery
```


Quick Starts
===

```go
import (
	"github.com/antchfx/xmlquery"
)

func main(){
	s := `<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
<channel>
  <title>W3Schools Home Page</title>
  <link>https://www.w3schools.com</link>
  <description>Free web building tutorials</description>
  <item>
    <title>RSS Tutorial</title>
    <link>https://www.w3schools.com/xml/xml_rss.asp</link>
    <description>New RSS tutorial on W3Schools</description>
  </item>
  <item>
    <title>XML Tutorial</title>
    <link>https://www.w3schools.com/xml</link>
    <description>New XML tutorial on W3Schools</description>
  </item>
</channel>
</rss>`

	doc, err := xmlquery.Parse(strings.NewReader(s))
	if err != nil {
		panic(err)
	}
	channel := xmlquery.FindOne(doc, "//channel")
	if n := channel.SelectElement("title"); n != nil {
		fmt.Printf("title: %s\n", n.InnerText())
	}
	if n := channel.SelectElement("link"); n != nil {
		fmt.Printf("link: %s\n", n.InnerText())
	}
	for i, n := range xmlquery.Find(doc, "//item/title") {
		fmt.Printf("#%d %s\n", i, n.InnerText())
	}
}
```

Getting Started
===

### Find specified XPath query.

```go
list, err := xmlquery.QueryAll(doc, "a")
if err != nil {
	panic(err)
}
```

#### Parse an XML from URL.

```go
doc, err := xmlquery.LoadURL("http://www.example.com/sitemap.xml")
```

#### Parse an XML from string.

```go
s := `<?xml version="1.0" encoding="utf-8"?><rss version="2.0"></rss>`
doc, err := xmlquery.Parse(strings.NewReader(s))
```

#### Parse an XML from io.Reader.

```go
f, err := os.Open("../books.xml")
doc, err := xmlquery.Parse(f)
```

#### Parse an XML in a stream fashion (simple case without elements filtering).

```go
f, err := os.Open("../books.xml")
p, err := xmlquery.CreateStreamParser(f, "/bookstore/book")
for {
	n, err := p.Read()
	if err == io.EOF {
		break
	}
	if err != nil {
		...
	}
}
```

#### Parse an XML in a stream fashion (simple case advanced element filtering).

```go
f, err := os.Open("../books.xml")
p, err := xmlquery.CreateStreamParser(f, "/bookstore/book", "/bookstore/book[price>=10]")
for {
	n, err := p.Read()
	if err == io.EOF {
		break
	}
	if err != nil {
		...
	}
}
```

#### Find authors of all books in the bookstore.

```go
list := xmlquery.Find(doc, "//book//author")
// or
list := xmlquery.Find(doc, "//author")
```

#### Find the second book.

```go
book := xmlquery.FindOne(doc, "//book[2]")
```

#### Find all book elements and only get `id` attribute. (New Feature)

```go
list := xmlquery.Find(doc,"//book/@id")
```

#### Find all books with id `bk104`.

```go
list := xmlquery.Find(doc, "//book[@id='bk104']")
```

#### Find all books with price less than 5.

```go
list := xmlquery.Find(doc, "//book[price<5]")
```

#### Evaluate total price of all books.

```go
expr, err := xpath.Compile("sum(//book/price)")
price := expr.Evaluate(xmlquery.CreateXPathNavigator(doc)).(float64)
fmt.Printf("total price: %f\n", price)
```

#### Evaluate number of all book elements.

```go
expr, err := xpath.Compile("count(//book)")
price := expr.Evaluate(xmlquery.CreateXPathNavigator(doc)).(float64)
```

FAQ
====

#### `Find()` vs `QueryAll()`, which is better?

`Find` and `QueryAll` both do the same thing: searches all of matched XML nodes.
`Find` panics if provided with an invalid XPath query, while `QueryAll` returns
an error.

#### Can I save my query expression object for the next query?

Yes, you can. We provide `QuerySelector` and `QuerySelectorAll` methods; they 
accept your query expression object.

Caching a query expression object avoids recompiling the XPath query 
expression, improving query performance.

#### Create XML document.

```go
doc := &xmlquery.Node{
	Type: xmlquery.DeclarationNode,
	Data: "xml",
	Attr: []xml.Attr{
		xml.Attr{Name: xml.Name{Local: "version"}, Value: "1.0"},
	},
}
root := &xmlquery.Node{
	Data: "rss",
	Type: xmlquery.ElementNode,
}
doc.FirstChild = root
channel := &xmlquery.Node{
	Data: "channel",
	Type: xmlquery.ElementNode,
}
root.FirstChild = channel
title := &xmlquery.Node{
	Data: "title",
	Type: xmlquery.ElementNode,
}
title_text := &xmlquery.Node{
	Data: "W3Schools Home Page",
	Type: xmlquery.TextNode,
}
title.FirstChild = title_text
channel.FirstChild = title
fmt.Println(doc.OutputXML(true))
// <?xml version="1.0"?><rss><channel><title>W3Schools Home Page</title></channel></rss>
```

Questions
===
Please let me know if you have any questions
