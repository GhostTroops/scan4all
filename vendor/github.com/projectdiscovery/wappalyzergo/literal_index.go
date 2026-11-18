package wappalyzer

// indexedPattern is one fingerprint pattern plus the app it belongs to.
type indexedPattern struct {
	pattern *ParsedPattern
	app     string
	implies []string
}

// literalIndex reports which patterns can match a folded string.
// Needles are found with one Aho-Corasick scan instead of one search per pattern.
type literalIndex struct {
	ac      *aho
	needles int
	items   []indexedPattern
	clauses [][][]int32
}

func (f *CompiledFingerprints) buildLiteralIndexes() {
	if f == nil {
		return
	}
	f.htmlIndex = buildLiteralIndex(f.Apps, func(fingerprint *CompiledFingerprint) []*ParsedPattern {
		return fingerprint.html
	})
	f.scriptIndex = buildScriptIndex(f.Apps)
}

// scriptLiteralIndex buckets script URLs by the first three bytes of each
// required literal. A URL is short, so a full automaton costs more memory
// than the scan it would save.
type scriptLiteralIndex struct {
	items   []indexedPattern
	buckets map[uint32][]int
	always  []int
}

func buildScriptIndex(apps map[string]*CompiledFingerprint) *scriptLiteralIndex {
	idx := &scriptLiteralIndex{buckets: make(map[uint32][]int)}
	for app, fingerprint := range apps {
		for _, pattern := range fingerprint.scriptSrc {
			if pattern == nil {
				continue
			}
			id := len(idx.items)
			idx.items = append(idx.items, indexedPattern{pattern: pattern, app: app, implies: fingerprint.implies})
			if pattern.SkipRegex || len(pattern.literals) == 0 {
				idx.always = append(idx.always, id)
				continue
			}
			for _, group := range pattern.literals {
				lit := longestLiteral(group)
				if len(lit) < 3 {
					idx.always = append(idx.always, id)
					break
				}
				key := uint32(lit[0])<<16 | uint32(lit[1])<<8 | uint32(lit[2])
				idx.buckets[key] = append(idx.buckets[key], id)
			}
		}
	}
	return idx
}

func longestLiteral(group []string) string {
	best := ""
	for _, lit := range group {
		if len(lit) > len(best) {
			best = lit
		}
	}
	return best
}

func (idx *scriptLiteralIndex) matching(folded string) map[*ParsedPattern]struct{} {
	hit := make(map[*ParsedPattern]struct{})
	for _, item := range idx.candidates(folded) {
		hit[item.pattern] = struct{}{}
	}
	return hit
}

func (idx *scriptLiteralIndex) match(data, folded string) []matchPartResult {
	return collectMatches(data, folded, idx.candidates(folded))
}

func (idx *scriptLiteralIndex) candidates(folded string) []indexedPattern {
	chosen := make([]indexedPattern, 0, len(idx.always))
	seen := make([]bool, len(idx.items))
	for _, id := range idx.always {
		seen[id] = true
		chosen = append(chosen, idx.items[id])
	}
	if len(folded) < 3 {
		return chosen
	}
	for i := 0; i+2 < len(folded); i++ {
		key := uint32(folded[i])<<16 | uint32(folded[i+1])<<8 | uint32(folded[i+2])
		for _, id := range idx.buckets[key] {
			if seen[id] {
				continue
			}
			seen[id] = true
			item := idx.items[id]
			if literalsPresent(folded, item.pattern.literals) {
				chosen = append(chosen, item)
			}
		}
	}
	return chosen
}

func collectMatches(data, folded string, chosen []indexedPattern) []matchPartResult {
	type acc struct {
		confidence int
		version    string
		implies    []string
	}
	grouped := make(map[string]*acc)
	for _, item := range chosen {
		valid, versionString := item.pattern.evaluate(data, folded)
		if !valid {
			continue
		}
		current := grouped[item.app]
		if current == nil {
			current = &acc{implies: item.implies}
			grouped[item.app] = current
		}
		if item.pattern.Confidence > current.confidence {
			current.confidence = item.pattern.Confidence
		}
		if versionString != "" && (current.version == "" || isMoreSpecific(versionString, current.version)) {
			current.version = versionString
		}
	}

	technologies := make([]matchPartResult, 0, len(grouped))
	for app, current := range grouped {
		technologies = append(technologies, matchPartResult{
			application: app,
			version:     current.version,
			confidence:  current.confidence,
		})
		for _, implied := range current.implies {
			technologies = append(technologies, matchPartResult{
				application: implied,
				confidence:  current.confidence,
			})
		}
	}
	return technologies
}

func buildLiteralIndex(apps map[string]*CompiledFingerprint, patterns func(*CompiledFingerprint) []*ParsedPattern) *literalIndex {
	idx := &literalIndex{ac: newAho()}
	known := make(map[string]int32)
	intern := func(lit string) int32 {
		if id, ok := known[lit]; ok {
			return id
		}
		id := int32(len(known))
		known[lit] = id
		idx.ac.add(lit, id)
		return id
	}

	for app, fingerprint := range apps {
		for _, pattern := range patterns(fingerprint) {
			if pattern == nil {
				continue
			}
			idx.items = append(idx.items, indexedPattern{pattern: pattern, app: app, implies: fingerprint.implies})
			if pattern.SkipRegex || len(pattern.literals) == 0 {
				idx.clauses = append(idx.clauses, nil)
				continue
			}
			groups := make([][]int32, len(pattern.literals))
			for i, group := range pattern.literals {
				ids := make([]int32, len(group))
				for j, lit := range group {
					ids[j] = intern(lit)
				}
				groups[i] = ids
			}
			idx.clauses = append(idx.clauses, groups)
		}
	}
	idx.needles = len(known)
	idx.ac.build()
	return idx
}

func (idx *literalIndex) matching(folded string) map[*ParsedPattern]struct{} {
	hit := make(map[*ParsedPattern]struct{})
	for _, item := range idx.candidates(folded) {
		hit[item.pattern] = struct{}{}
	}
	return hit
}

func (idx *literalIndex) match(data, folded string) []matchPartResult {
	return collectMatches(data, folded, idx.candidates(folded))
}

func (idx *literalIndex) candidates(folded string) []indexedPattern {
	present := make([]bool, idx.needles)
	if idx.ac != nil && folded != "" {
		idx.ac.visit(folded, present)
	}
	chosen := make([]indexedPattern, 0)
	for i, item := range idx.items {
		groups := idx.clauses[i]
		if len(groups) == 0 || clausesHit(groups, present) {
			chosen = append(chosen, item)
		}
	}
	return chosen
}

func clausesHit(groups [][]int32, present []bool) bool {
	for _, group := range groups {
		matched := true
		for _, id := range group {
			if int(id) >= len(present) || !present[id] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// aho is an ASCII Aho-Corasick automaton. Node 0 is the root, and a next
// value of 0 means there is no edge.
type aho struct {
	nodes []ahoNode
}

type ahoNode struct {
	next [128]int32
	fail int32
	out  []int32
}

func newAho() *aho {
	return &aho{nodes: []ahoNode{{}}}
}

func (a *aho) add(literal string, id int32) {
	state := int32(0)
	for i := 0; i < len(literal); i++ {
		c := literal[i]
		if c >= 128 {
			return
		}
		next := a.nodes[state].next[c]
		if next == 0 {
			a.nodes = append(a.nodes, ahoNode{})
			next = int32(len(a.nodes) - 1)
			a.nodes[state].next[c] = next
		}
		state = next
	}
	a.nodes[state].out = append(a.nodes[state].out, id)
}

func (a *aho) build() {
	queue := make([]int32, 0, len(a.nodes))
	for c := 0; c < 128; c++ {
		if next := a.nodes[0].next[c]; next != 0 {
			queue = append(queue, next)
		}
	}
	for head := 0; head < len(queue); head++ {
		parent := queue[head]
		for c := 0; c < 128; c++ {
			node := a.nodes[parent].next[c]
			if node == 0 {
				continue
			}
			queue = append(queue, node)
			fail := a.nodes[parent].fail
			for fail != 0 && a.nodes[fail].next[c] == 0 {
				fail = a.nodes[fail].fail
			}
			if next := a.nodes[fail].next[c]; next != 0 && next != node {
				fail = next
			} else {
				fail = 0
			}
			a.nodes[node].fail = fail
			if len(a.nodes[fail].out) == 0 {
				continue
			}
			merged := make([]int32, len(a.nodes[node].out)+len(a.nodes[fail].out))
			copy(merged, a.nodes[node].out)
			copy(merged[len(a.nodes[node].out):], a.nodes[fail].out)
			a.nodes[node].out = merged
		}
	}
	a.completeTransitions()
}

// completeTransitions fills missing edges with the failure target so a search
// is one lookup per byte.
func (a *aho) completeTransitions() {
	queue := make([]int32, 0, len(a.nodes))
	seen := make([]bool, len(a.nodes))
	seen[0] = true
	for c := 0; c < 128; c++ {
		if next := a.nodes[0].next[c]; next != 0 {
			seen[next] = true
			queue = append(queue, next)
		}
	}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		fail := a.nodes[node].fail
		for c := 0; c < 128; c++ {
			child := a.nodes[node].next[c]
			if child == 0 {
				a.nodes[node].next[c] = a.nodes[fail].next[c]
				continue
			}
			if !seen[child] {
				seen[child] = true
				queue = append(queue, child)
			}
		}
	}
}

func (a *aho) visit(text string, present []bool) {
	var state int32
	nodes := a.nodes
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 128 {
			state = 0
			continue
		}
		state = nodes[state].next[c]
		for _, id := range nodes[state].out {
			if int(id) < len(present) {
				present[id] = true
			}
		}
	}
}
