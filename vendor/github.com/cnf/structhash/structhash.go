package structhash

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Version returns the version of the supplied hash as an integer
// or -1 on failure
func Version(h string) int {
	if h == "" {
		return -1
	}
	if h[0] != 'v' {
		return -1
	}
	if spos := strings.IndexRune(h[1:], '_'); spos >= 0 {
		n, e := strconv.Atoi(h[1 : spos+1])
		if e != nil {
			return -1
		}
		return n
	}
	return -1
}

// Hash takes a data structure and returns a hash string of that data structure
// at the version asked.
//
// This function uses md5 hashing function and default formatter. See also Dump()
// function.
func Hash(c interface{}, version int) (string, error) {
	return fmt.Sprintf("v%d_%x", version, Md5(c, version)), nil
}

// Dump takes a data structure and returns its byte representation. This can be
// useful if you need to use your own hashing function or formatter.
func Dump(c interface{}, version int) []byte {
	return serialize(c, version)
}

// Md5 takes a data structure and returns its md5 hash.
// This is a shorthand for md5.Sum(Dump(c, version)).
func Md5(c interface{}, version int) []byte {
	sum := md5.Sum(Dump(c, version))
	return sum[:]
}

// Sha1 takes a data structure and returns its sha1 hash.
// This is a shorthand for sha1.Sum(Dump(c, version)).
func Sha1(c interface{}, version int) []byte {
	sum := sha1.Sum(Dump(c, version))
	return sum[:]
}

type item struct {
	name  string
	value reflect.Value
}

type itemSorter []item

func (s itemSorter) Len() int {
	return len(s)
}

func (s itemSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s itemSorter) Less(i, j int) bool {
	return s[i].name < s[j].name
}

type tagError string

func (e tagError) Error() string {
	return "incorrect tag " + string(e)
}

type structFieldFilter func(reflect.StructField, *item) (bool, error)

func writeValue(buf *bytes.Buffer, val reflect.Value, fltr structFieldFilter) {
	switch val.Kind() {
	case reflect.String:
		buf.WriteByte('"')
		buf.WriteString(val.String())
		buf.WriteByte('"')
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buf.WriteString(strconv.FormatInt(val.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		buf.WriteString(strconv.FormatUint(val.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		buf.WriteString(strconv.FormatFloat(val.Float(), 'E', -1, 64))
	case reflect.Bool:
		if val.Bool() {
			buf.WriteByte('t')
		} else {
			buf.WriteByte('f')
		}
	case reflect.Ptr:
		if !val.IsNil() || val.Type().Elem().Kind() == reflect.Struct {
			writeValue(buf, reflect.Indirect(val), fltr)
		} else {
			writeValue(buf, reflect.Zero(val.Type().Elem()), fltr)
		}
	case reflect.Array, reflect.Slice:
		buf.WriteByte('[')
		len := val.Len()
		for i := 0; i < len; i++ {
			if i != 0 {
				buf.WriteByte(',')
			}
			writeValue(buf, val.Index(i), fltr)
		}
		buf.WriteByte(']')
	case reflect.Map:
		mk := val.MapKeys()
		items := make([]item, len(mk), len(mk))
		// Get all values
		for i, _ := range items {
			items[i].name = formatValue(mk[i], fltr)
			items[i].value = val.MapIndex(mk[i])
		}

		// Sort values by key
		sort.Sort(itemSorter(items))

		buf.WriteByte('[')
		for i, _ := range items {
			if i != 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(items[i].name)
			buf.WriteByte(':')
			writeValue(buf, items[i].value, fltr)
		}
		buf.WriteByte(']')
	case reflect.Struct:
		vtype := val.Type()
		flen := vtype.NumField()
		items := make([]item, 0, flen)
		// Get all fields
		for i := 0; i < flen; i++ {
			field := vtype.Field(i)
			it := item{field.Name, val.Field(i)}
			if fltr != nil {
				ok, err := fltr(field, &it)
				if err != nil && strings.Contains(err.Error(), "method:") {
					panic(err)
				}
				if !ok {
					continue
				}
			}
			items = append(items, it)
		}
		// Sort fields by name
		sort.Sort(itemSorter(items))

		buf.WriteByte('{')
		for i, _ := range items {
			if i != 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(items[i].name)
			buf.WriteByte(':')
			writeValue(buf, items[i].value, fltr)
		}
		buf.WriteByte('}')
	case reflect.Interface:
		if !val.CanInterface() {
			return
		}
		writeValue(buf, reflect.ValueOf(val.Interface()), fltr)
	default:
		buf.WriteString(val.String())
	}
}

func formatValue(val reflect.Value, fltr structFieldFilter) string {
	if val.Kind() == reflect.String {
		return "\"" + val.String() + "\""
	}

	var buf bytes.Buffer
	writeValue(&buf, val, fltr)

	return string(buf.Bytes())
}

func filterField(f reflect.StructField, i *item, version int) (bool, error) {
	var err error
	ver := 0
	lastver := -1
	if str := f.Tag.Get("hash"); str != "" {
		if str == "-" {
			return false, nil
		}
		for _, tag := range strings.Split(str, " ") {
			args := strings.Split(strings.TrimSpace(tag), ":")
			if len(args) != 2 {
				return false, tagError(tag)
			}
			switch args[0] {
			case "name":
				i.name = args[1]
			case "version":
				if ver, err = strconv.Atoi(args[1]); err != nil {
					return false, tagError(tag)
				}
			case "lastversion":
				if lastver, err = strconv.Atoi(args[1]); err != nil {
					return false, tagError(tag)
				}
			case "method":
				property, found := f.Type.MethodByName(strings.TrimSpace(args[1]))
				if !found || property.Type.NumOut() != 1 {
					return false, tagError(tag)
				}
				i.value = property.Func.Call([]reflect.Value{i.value})[0]
			}
		}
	} else {
		if str := f.Tag.Get("lastversion"); str != "" {
			if lastver, err = strconv.Atoi(str); err != nil {
				return false, tagError(str)
			}
		}
		if str := f.Tag.Get("version"); str != "" {
			if ver, err = strconv.Atoi(str); err != nil {
				return false, tagError(str)
			}
		}
	}
	if lastver != -1 && lastver < version {
		return false, nil
	}
	if ver > version {
		return false, nil
	}
	return true, nil
}

func serialize(object interface{}, version int) []byte {
	var buf bytes.Buffer

	writeValue(&buf, reflect.ValueOf(object),
		func(f reflect.StructField, i *item) (bool, error) {
			return filterField(f, i, version)
		})

	return buf.Bytes()
}
