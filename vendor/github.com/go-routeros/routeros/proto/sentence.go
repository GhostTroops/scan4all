package proto

import "fmt"

// Sentence is a line read from a RouterOS device.
type Sentence struct {
	// Word that begins with !
	Word string
	Tag  string
	List []Pair
	Map  map[string]string
}

type Pair struct {
	Key, Value string
}

func NewSentence() *Sentence {
	return &Sentence{
		Map: make(map[string]string),
	}
}

func (sen *Sentence) String() string {
	return fmt.Sprintf("%s @%s %#q", sen.Word, sen.Tag, sen.List)
}
