package smap

import (
	"fmt"
	"testing"
)

func TestSMap_Length(t *testing.T) {
	s := New()
	s.Set("aaaa", "bbbb")
	s.Set("aaaa", "bbbb")
	s.Set("aaaa", "bbbb")
	s.Set("aaaa", "bbbb")
	s.Set("aaaa", "bbbb")
	s.Set("BBBB", "bbbb")
	s.Delete("BBBB")
	s.Delete("cccc")
	fmt.Println(s.Peek())
}
