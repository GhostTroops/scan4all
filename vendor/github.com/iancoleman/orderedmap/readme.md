# orderedmap

A golang data type equivalent to python's collections.OrderedDict

Retains order of keys in maps

Can be JSON serialized / deserialized

# Usage

```go
package main

import (
    "encoding/json"
    "github.com/iancoleman/orderedmap"
)

func main() {

    // use New() instead of o := map[string]interface{}{}
    o := orderedmap.New()

    // use Set instead of o["a"] = 1
    o.Set("a", 1)

    // use Get instead of i, ok := o["a"]
    val, ok := o.Get("a")

    // use Keys instead of for k, v := range o
    key := o.Keys()
    for _, k := range keys {
        v, _ := o.Get(k)
    }

    // use o.Delete instead of delete(o, key)
    err := o.Delete("a")

    // serialize to a json string using encoding/json
    bytes, err := json.Marshal(o)
    prettyBytes, err := json.MarshalIndent(o)

    // deserialize a json string using encoding/json
    // all maps (including nested maps) will be parsed as orderedmaps
    s := `{"a": 1}`
    err := json.Unmarshal([]byte(s), &o)
    
    // sort the keys
    o.SortKeys(sort.Strings)
    
    // sort by Pair
    o.Sort(func(a *Pair, b *Pair) bool {
        return a.Value().(float64) < b.Value().(float64)
    })
}
```

# Caveats

* OrderedMap only takes strings for the key, as per [the JSON spec](http://json.org/).

# Tests

```
go test
```

# Alternatives

None of the alternatives offer JSON serialization.

* [cevaris/ordered_map](https://github.com/cevaris/ordered_map)
* [mantyr/iterator](https://github.com/mantyr/iterator)
