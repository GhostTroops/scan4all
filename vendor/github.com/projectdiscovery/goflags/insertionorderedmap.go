package goflags

type InsertionOrderedMap struct {
	values map[string]*FlagData
	keys   []string `yaml:"-"`
}

func (insertionOrderedMap *InsertionOrderedMap) forEach(fn func(key string, data *FlagData)) {
	for _, key := range insertionOrderedMap.keys {
		fn(key, insertionOrderedMap.values[key])
	}
}

func (insertionOrderedMap *InsertionOrderedMap) Set(key string, value *FlagData) {
	_, present := insertionOrderedMap.values[key]
	insertionOrderedMap.values[key] = value
	if !present {
		insertionOrderedMap.keys = append(insertionOrderedMap.keys, key)
	}
}
