package detect

// keywordIndex finds, in one pass over a text, every rule whose keywords occur
// in it, ASCII case-insensitively. It is an Aho-Corasick automaton compiled to
// a full transition table over the bytes the keywords use, so the scan is one
// table lookup per byte however many rules there are.
//
// It replaces lowering the whole text and calling strings.Contains once per
// keyword, which read the text a few hundred times with gitleaks' rules.
type keywordIndex struct {
	rules int
	// always lists the rules every text runs: those without keywords, and
	// those with a non-ASCII keyword, which ASCII folding cannot match safely.
	always []int
	// class maps a byte, after ASCII lowercasing, to its column in next;
	// column 0 is every byte no keyword uses.
	class  [256]uint8
	width  int
	next   []int32
	output [][]int
}

func newKeywordIndex(rules []secretRule) *keywordIndex {
	k := &keywordIndex{rules: len(rules)}
	var keywords [][]byte
	var owners [][]int
	seen := map[string]int{}
	for i, r := range rules {
		if len(r.keywords) == 0 || !asciiOnly(r.keywords) {
			k.always = append(k.always, i)
			continue
		}
		for _, kw := range r.keywords {
			if kw == "" {
				continue
			}
			word := []byte(kw)
			for j, b := range word {
				word[j] = lowerByte(b)
			}
			if at, ok := seen[string(word)]; ok {
				owners[at] = append(owners[at], i)
				continue
			}
			seen[string(word)] = len(keywords)
			keywords = append(keywords, word)
			owners = append(owners, []int{i})
		}
	}

	k.width = 1
	for _, word := range keywords {
		for _, b := range word {
			if k.class[b] == 0 {
				k.class[b] = uint8(k.width)
				k.width++
			}
		}
	}
	// Upper-case ASCII letters share their lower-case letter's column.
	for b := 'A'; b <= 'Z'; b++ {
		k.class[b] = k.class[b+'a'-'A']
	}

	// The trie: goto[state*width+column], -1 where there is no edge yet.
	k.next = []int32{}
	k.output = [][]int{nil}
	k.next = append(k.next, make([]int32, k.width)...)
	for i := range k.next {
		k.next[i] = -1
	}
	for w, word := range keywords {
		state := int32(0)
		for _, b := range word {
			at := int(state)*k.width + int(k.class[b])
			if k.next[at] < 0 {
				k.next[at] = int32(len(k.output))
				k.output = append(k.output, nil)
				row := make([]int32, k.width)
				for i := range row {
					row[i] = -1
				}
				k.next = append(k.next, row...)
			}
			state = k.next[at]
		}
		k.output[state] = append(k.output[state], owners[w]...)
	}

	// Breadth first, turn the trie into a full automaton: a missing edge goes
	// where the failure link's edge goes, and a state also reports what its
	// failure link reports.
	fail := make([]int32, len(k.output))
	queue := make([]int32, 0, len(k.output))
	for c := 0; c < k.width; c++ {
		if s := k.next[c]; s < 0 {
			k.next[c] = 0
		} else {
			fail[s] = 0
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for c := 0; c < k.width; c++ {
			at := int(state)*k.width + c
			s := k.next[at]
			if s < 0 {
				k.next[at] = k.next[int(fail[state])*k.width+c]
				continue
			}
			fail[s] = k.next[int(fail[state])*k.width+c]
			k.output[s] = append(k.output[s], k.output[fail[s]]...)
			queue = append(queue, s)
		}
	}
	return k
}

// scan reports, for each rule, whether the text should run it.
func (k *keywordIndex) scan(text string) []bool {
	applies := make([]bool, k.rules)
	for _, i := range k.always {
		applies[i] = true
	}
	if len(k.output) == 1 {
		return applies
	}
	state := int32(0)
	for i := 0; i < len(text); i++ {
		state = k.next[int(state)*k.width+int(k.class[text[i]])]
		for _, r := range k.output[state] {
			applies[r] = true
		}
	}
	return applies
}

func asciiOnly(words []string) bool {
	for _, w := range words {
		for i := 0; i < len(w); i++ {
			if w[i] >= 0x80 {
				return false
			}
		}
	}
	return true
}
