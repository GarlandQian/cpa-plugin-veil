package detect

import (
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// contextRules find vendor keys by their prefix, secrets and passwords by
// what is written around them, and personal data by its shape and checks.
// The vendor keys are the gitleaks rules' too; these find them without an
// entropy threshold, which a key of repeated characters can fall short of.
var contextRules = []rule{
	{id: "vendor-sk", kind: KindSecret, cat: catSecrets, markers: []string{"sk-"}, bound: tokenCh, ok: notASlug,
		re: regexp.MustCompile(`sk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)},
	{id: "vendor-relay-sk", kind: KindSecret, cat: catSecrets, markers: []string{"_sk_"}, bound: tokenCh, ok: secretValue,
		re: regexp.MustCompile(`[a-z]{2,4}_sk_[A-Za-z0-9_-]{20,}`)},
	{id: "vendor-ark", kind: KindSecret, cat: catSecrets, markers: []string{"ark-"}, bound: tokenCh, ok: secretValue,
		re: regexp.MustCompile(`ark-[A-Za-z0-9][A-Za-z0-9_-]{15,}`)},
	{id: "vendor-git", kind: KindSecret, cat: catSecrets, markers: []string{"gh", "github_pat_", "glpat-"}, bound: tokenCh,
		re: regexp.MustCompile(`(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,})`)},
	{id: "vendor-google", kind: KindSecret, cat: catSecrets, markers: []string{"AIza"}, bound: tokenCh,
		re: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{id: "vendor-slack", kind: KindSecret, cat: catSecrets, markers: []string{"xox"}, bound: tokenCh,
		re: regexp.MustCompile(`xox[abposr]-[0-9A-Za-z-]{10,}`)},
	{id: "vendor-stripe", kind: KindSecret, cat: catSecrets, markers: []string{"_live_"}, bound: tokenCh,
		re: regexp.MustCompile(`(?:sk|rk)_live_[0-9A-Za-z]{20,}`)},
	{id: "vendor-aws", kind: KindSecret, cat: catSecrets, markers: []string{"AKIA", "ASIA"}, bound: alnum,
		re: regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`)},
	{id: "vendor-other", kind: KindSecret, cat: catSecrets, markers: []string{"hf_", "gsk_", "xai-", "npm_", "pypi-", "dop_v1_", "SG."}, bound: tokenCh,
		re: regexp.MustCompile(`(?:hf_[A-Za-z0-9]{30,}|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|dop_v1_[a-f0-9]{64}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})`)},
	{id: "jwt", kind: KindSecret, cat: catSecrets, markers: []string{"eyJ"}, bound: tokenCh,
		re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},

	{id: "private-key-block", kind: KindPrivateKey, cat: catSecrets, markers: []string{"PRIVATE KEY"},
		re: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	// the password of user:password@host, or of :password@host as a Redis
	// URL has it with no user
	{id: "url-password", kind: KindPassword, cat: catSecrets, markers: []string{"://"}, ok: notAVariable, at: hiddenInURL,
		re: regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:@/?#"'<>]*:([^\s@/?#"'<>]{3,})@`)},
	// password = …, API_KEY: "…", as .env files and configs have them
	{id: "named-secret", kind: KindSecret, cat: catSecrets, markers: secretNames.markers(), ok: secretValue, at: fieldAt,
		re: regexp.MustCompile(`(?i)[A-Za-z0-9_.-]*(?:` + secretNames.pattern() + `)[A-Za-z0-9_.-]*` + quote + `[ \t]*[:=][ \t]*` + quote + `(` + secretCh + `{8,})`)},
	// an env var's name says what it holds in the upper case: a
	// SERVICE_X_KEY, a DB_PASS; in the lower case a name ending in key is
	// code's (a sort key, a cache key)
	{id: "env-secret", kind: KindSecret, cat: catSecrets, markers: fieldNames{{"key", "key"}, {"pass", "pass"}}.markers(), ok: secretValue, at: namedSecretAt,
		re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])[A-Za-z0-9_.-]*_(?:KEY|PASS)` + quote + `[ \t]*[:=][ \t]*` + quote + `(` + secretCh + `{8,})`)},
	// an Authorization or Cookie header's value is a secret whatever it
	// looks like
	{id: "auth-header", kind: KindSecret, cat: catSecrets, markers: fieldNames{{"authorization", "authorization"}, {"cookie", "cookie"}}.markers(), ok: headerValue,
		re: regexp.MustCompile(`(?im)^[ \t]*(?:authorization|cookie)[ \t]*:[ \t]*(\S[^\r\n]{7,})`)},
	// a field called key and nothing more: "key": "oc_sk_…"; only a long
	// value of letters and digits both, since code calls anything a key
	{id: "key-field", kind: KindSecret, cat: catSecrets, markers: fieldNames{{"key", "key"}}.markers(), ok: secretValue, at: fieldAt,
		re: regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_.-])` + quote + `key` + quote + `[ \t]*[:=][ \t]*` + quote + `(` + secretCh + `{16,})`)},
	// a password after its name in Chinese, Japanese or Korean: 密码：786kih
	{id: "cjk-password", kind: KindPassword, cat: catSecrets, re: cjkNamed(cjkPasswordNames), fold: lowerAll(cjkPasswordNames), back: 64, ahead: 100, ok: notAVariable},
	// a key, a secret or a token after its name the same way: 密钥为 …
	{id: "cjk-secret", kind: KindSecret, cat: catSecrets, re: cjkNamed(cjkKeyNames), fold: lowerAll(cjkKeyNames), back: 64, ahead: 100, at: keyAt},
	// an English name for one before 为, 為, 是 or ：: apikey 为 …
	{id: "copula-secret", kind: KindSecret, cat: catSecrets, fold: cjkCopulas, back: 24, ahead: 260, at: keyAt,
		re: regexp.MustCompile(`(?i)(?:` + secretNames.pattern() + `|pwd|api[ ]key|access[ ]key|secret[ ]key|key|\bpin(?:[ ]?code)?)` + quote +
			`[ \t]*(?:[为為是][ \t]*[:：]?|：)[ \t]*(?:\\?["'“「])?(` + secretCh + `{3,}[A-Za-z0-9_\-/+=~!@#%^&*])`)},

	{id: "email", kind: KindEmail, cat: catPersonal, markers: []string{"@"}, bound: alnum + "%+-", fix: emailFix, at: emailAt,
		re: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)},
	{id: "id-card-cn", kind: KindIDCard, cat: catPersonal, bound: alnum, ok: chineseID,
		re: regexp.MustCompile(`[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)},
	{id: "phone-cn", kind: KindPhone, cat: catPersonal, bound: alnum, at: phoneAt,
		re: regexp.MustCompile(`(?:\+?86[- ]?)?1[3-9]\d{9}`)},
	{id: "bank-card", kind: KindBankCard, cat: catPersonal, bound: alnum, ok: luhn,
		re: regexp.MustCompile(`[3-6]\d{3}(?:[ -]?\d{4}){2,3}(?:[ -]?\d{1,3})?`)},
}

// cjkPasswordNames are what a password is called in Chinese, Japanese and
// Korean.
var cjkPasswordNames = []string{"密码", "密碼", "口令", "PIN码", "PIN碼", "PIN 码", "安全码", "安全碼", "パスワード", "暗証番号", "비밀번호", "암호", "비번"}

// cjkKeyNames are what a key, a secret or a token is called in Chinese,
// Japanese and Korean.
var cjkKeyNames = []string{
	"密钥", "密鑰", "秘钥", "秘鑰", "私钥", "私鑰", "金钥", "金鑰", "令牌", "权杖", "權杖", "授权码", "授權碼",
	"秘密鍵", "トークン", "シークレット", "APIキー", "アクセスキー",
	"토큰", "비밀키", "API 키", "API키",
}

// cjkCopulas are what stands between a name and its value in a Chinese
// message.
var cjkCopulas = []string{"为", "為", "是", "："}

func lowerAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.ToLower(n)
	}
	return out
}

// cjkNamed is a value after one of names: after ：, :, =, 为, 為, 是, は
// or 는, quoted or not, or after nothing but a space.
func cjkNamed(names []string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)(?:` + strings.Join(names, "|") + `)[ \t]*(?:[:：=][ \t]*|[为為是][ \t]*[:：]?[ \t]*|は[ \t]*|는[ \t]*)?(?:\\?["'“「])?(` + secretCh + `{3,63}[A-Za-z0-9_\-/+=~!@#%^&*])`)
}

// fieldNames are what a field that holds a secret is called: a pattern for
// each name, and text that any match of it has in it.
type fieldNames []struct{ re, marker string }

// secretNames are what a field holding a secret has in its name.
var secretNames = fieldNames{
	{"password", "pass"}, {"passwd", "pass"},
	{"secret", "secret"},
	{"token", "token"},
	{`api[_-]?key`, "key"}, {`access[_-]?key`, "key"}, {`private[_-]?key`, "key"},
	{"credential", "credential"},
}

func (f fieldNames) pattern() string {
	res := make([]string, len(f))
	for i, n := range f {
		res[i] = n.re
	}
	return strings.Join(res, "|")
}

// markers are each name's marker in lower case, upper case and
// capitalised.
func (f fieldNames) markers() []string {
	var out []string
	for _, n := range f {
		for _, m := range []string{n.marker, strings.ToUpper(n.marker), strings.ToUpper(n.marker[:1]) + n.marker[1:]} {
			if !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

const (
	// quote is a field's or a value's quote, if it has one
	quote = `(?:\\?["'])?`
	// secretCh are the characters of a secret's value
	secretCh = `[A-Za-z0-9_\-./+=~!@#%^&*]`
)

// secretFieldName is a field's or header's name that says its value is a
// secret: a token, a key, a password or a cookie. A name that ends in pass
// (a db_pass) is one too; a name that only ends in key is not.
var secretFieldName = regexp.MustCompile(`(?i)` + secretNames.pattern() + `|authori[sz]ation|cookie|^key$|^pass$|_pass$`)

// secretField says a field called name holds a secret whatever its value
// looks like, as {"api_key": "…"} or "Authorization" do: a value of 8
// characters or more that does not stand for a variable. A count of tokens
// (max_tokens) is no secret.
func secretField(name, value string) bool {
	n := strings.ToLower(name)
	return len(value) >= 8 && notAVariable(value) && secretFieldName.MatchString(n) &&
		!strings.HasSuffix(n, "tokens") && !strings.HasSuffix(n, "token_count")
}

// notAVariable turns away what stands in for a value: ${PASS}, <password>,
// ****, and an escape where the value would start, the line having ended
// (KEY: \nnext in JSON written out as text).
func notAVariable(v string) bool {
	if strings.ContainsAny(v[:1], "$%{<[*\\") {
		return false
	}
	return strings.Trim(v, "*xX.") != ""
}

// keyValue is a key's or a token's value, not a word or a number: letters
// and digits both, or 16 characters or more that aren't all digits.
func keyValue(v string) bool {
	if !notAVariable(v) {
		return false
	}
	letter := strings.IndexFunc(v, func(r rune) bool { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }) >= 0
	return letter && (strings.ContainsAny(v, digits) || len(v) >= 16)
}

// keyAt is keyValue for s[a:b], or six digits or more right after a
// separator that count nothing: 密钥为12231241 is a key, 密钥为 2048 位 a
// size.
func keyAt(s string, a, b int) bool {
	v := s[a:b]
	if pathValue(v) || versionValue(v) {
		return false
	}
	if keyValue(v) {
		return true
	}
	if len(v) < 6 || strings.Trim(v, digits) != "" {
		return false
	}
	before := strings.TrimRight(s[:a], " \t\"'“「\\")
	after := strings.TrimLeft(s[b:], " \t")
	return slices.ContainsFunc(keySeparators, func(c string) bool { return strings.HasSuffix(before, c) }) &&
		!slices.ContainsFunc(quantityUnits, func(u string) bool { return strings.HasPrefix(after, u) })
}

var keySeparators = []string{"为", "為", "是", "：", ":", "=", "は", "는"}

var quantityUnits = []string{"位", "比特", "字节", "字節", "个", "個", "次", "秒", "毫秒", "分钟", "分鐘", "小时", "小時", "天", "年", "bit", "byte", "ms", "sec", "min", "ビット", "バイト", "비트", "바이트"}

// secretValue is a value that looks like a secret, not code: letters and
// digits both, and not a call, a reference or a placeholder of its own.
func secretValue(v string) bool {
	if !notAVariable(v) || strings.HasPrefix(v, "process.env") || strings.HasPrefix(v, "os.") {
		return false
	}
	return strings.ContainsAny(v, digits) && strings.IndexFunc(v, func(r rune) bool { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }) >= 0
}

// identPath is a name in code, or a field read through one.
var identPath = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$`)

// notCode turns away a value that is code naming a secret, not the secret:
// a call, or, unquoted after a colon, a type or a read code goes on from.
func notCode(s string, a, b int) bool {
	if !identPath.MatchString(s[a:b]) {
		return true
	}
	rest := strings.TrimLeft(s[b:], " \t")
	if strings.HasPrefix(rest, "(") {
		return false
	}
	if a > 0 && (s[a-1] == '"' || s[a-1] == '\'') || !strings.HasSuffix(strings.TrimRight(s[:a], " \t"), ":") {
		return true
	}
	return rest == "" || !strings.ContainsRune(";,)}]|?&<>", rune(rest[0]))
}

// emailAt is where an email at s[a:b] can be: not in a URL's userinfo,
// not a login on an ssh, scp or rsync line, and with no dot touching it
// that makes it part of a longer name.
func emailAt(s string, a, b int) bool {
	if a > 0 && s[a-1] == '.' {
		return false
	}
	if b+1 < len(s) && s[b] == '.' && strings.IndexByte(tokenCh, s[b+1]) >= 0 {
		return false
	}
	// No domain has an underscore, so one after the address ends it, as
	// Markdown's emphasis does (_a@b.cn_); a word after the underscores
	// makes it a longer name instead (x@self.in_proj).
	if e := b; e < len(s) && s[e] == '_' {
		for e < len(s) && s[e] == '_' {
			e++
		}
		if e < len(s) && strings.IndexByte(alnum, s[e]) >= 0 {
			return false
		}
	}
	return !inUserinfo(s, a) && !inRemoteCommand(s, a)
}

// emailFix leaves out the underscores Markdown puts before an address it
// emphasises (_a@b.cn_, __a@b.cn__) and the letter of an escape before it
// (origin\tgit@github.com in JSON written out as text), which the local
// part's pattern takes in, and checks what is left is a mailbox.
func emailFix(s string, a, b int) (int, int, bool) {
	if a > 0 && s[a-1] == '\\' && strings.IndexByte("nrtbf", s[a]) >= 0 {
		a++
	}
	if b < len(s) && s[b] == '_' {
		for a < b && s[a] == '_' {
			a++
		}
	}
	return a, b, strings.IndexByte(s[a:b], '@') > 0 && realEmail(s[a:b])
}

// remoteCommands are the commands a user@host after which is a login, not
// a mailbox; the userhost Category masks those.
var remoteCommands = []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "}

// inRemoteCommand says the line s[a] is on runs ssh, scp or rsync before it.
func inRemoteCommand(s string, a int) bool {
	line := s[strings.LastIndexByte(s[:a], '\n')+1 : a]
	for _, cmd := range remoteCommands {
		if strings.Contains(line, cmd) {
			return true
		}
	}
	return false
}

// inUserinfo says s[a] is inside a URL's authority, after its scheme://
// and before the host.
func inUserinfo(s string, a int) bool {
	i := a
	for i > 0 && !strings.ContainsRune(" \t\r\n/?#\"'<>@`", rune(s[i-1])) {
		i--
	}
	if i < 3 || s[i-1] != '/' || s[i-2] != '/' || s[i-3] != ':' {
		return false
	}
	j := i - 3
	k := j
	for k > 0 && (s[k-1] >= 'a' && s[k-1] <= 'z' || s[k-1] >= 'A' && s[k-1] <= 'Z' || s[k-1] >= '0' && s[k-1] <= '9' || strings.IndexByte("+.-", s[k-1]) >= 0) {
		k--
	}
	for k < j && !(s[k] >= 'a' && s[k] <= 'z' || s[k] >= 'A' && s[k] <= 'Z') {
		k++
	}
	return k < j
}

// hiddenInURL says the password at s[a:b], in a URL's user:password@, is
// hidden by masking it: it is not also its user name or a part of its
// host or path, as postgres:postgres@… has it.
func hiddenInURL(s string, a, b int) bool {
	pw := s[a:b]
	i := strings.LastIndex(s[:a], "//")
	if i < 0 || s[a-1] != ':' {
		return true
	}
	if s[i+2:a-1] == pw {
		return false
	}
	end := b + 1
	for end < len(s) && !strings.ContainsRune(" \t\r\n\"'<>`\\)]}", rune(s[end])) {
		end++
	}
	if b+1 > end {
		return true
	}
	// A URL to a host kept for examples is a fixture's, its password too.
	host := s[b+1 : end]
	if i := strings.IndexAny(host, "/:?#"); i >= 0 {
		host = host[:i]
	}
	if exampleHost(strings.ToLower(host)) {
		return false
	}
	for _, part := range strings.FieldsFunc(s[b+1:end], func(r rune) bool { return strings.ContainsRune("/:.?#&=;,@", r) }) {
		if part == pw {
			return false
		}
	}
	return true
}

// notASlug is false for words in lower case joined by hyphens, as a page's
// address has them; a key has a capital or a long random run.
func notASlug(v string) bool {
	if strings.ContainsFunc(v, func(r rune) bool { return r >= 'A' && r <= 'Z' }) {
		return true
	}
	if !strings.ContainsFunc(strings.TrimPrefix(v, "sk-"), func(r rune) bool {
		return r != '-' && r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'f')
	}) {
		return true
	}
	for _, w := range strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(w) >= 16 {
			return true
		}
	}
	return false
}

// headerValue says the rest of an Authorization or Cookie line is a
// header's value, not prose that begins with the word.
func headerValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || !notAVariable(v) {
		return false
	}
	notLetter := func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') }
	f := strings.Fields(v)
	if len(f) == 1 || len(f) == 2 && strings.IndexFunc(f[0], notLetter) < 0 {
		cred := f[len(f)-1]
		return len(cred) >= 8 && notAVariable(cred) && strings.IndexFunc(cred, notLetter) >= 0
	}
	for _, kv := range strings.Split(v, ";") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return false
		}
	}
	return strings.Contains(v, "=")
}

// notAPlainKey turns away the upper-case name before the value when it only
// ends in key and holds no secret: a sort key, a cache key, a public key.
func notAPlainKey(s string, a, b int) bool {
	i := a
	for i > 0 && strings.IndexByte(`"' `+"\t:=", s[i-1]) >= 0 {
		i--
	}
	end := i
	for i > 0 && strings.IndexByte(alnum+"_.-", s[i-1]) >= 0 {
		i--
	}
	name := strings.ToLower(s[i:end])
	return !strings.HasSuffix(name, "sort_key") && !strings.HasSuffix(name, "cache_key") &&
		!strings.HasSuffix(name, "prompt_cache_key") && !strings.HasSuffix(name, "public_key")
}

func namedSecretAt(s string, a, b int) bool {
	return notAPlainKey(s, a, b) && notCode(s, a, b) && fieldAt(s, a, b)
}

// realEmail is whether v, matched as an address, is someone's: not git@,
// not a linker's symbol, not a file named @2x, not a documentation domain,
// and on a top-level domain mail can reach.
func realEmail(v string) bool {
	at := strings.LastIndexByte(v, '@')
	if strings.EqualFold(v[:at], "git") {
		return false
	}
	host := strings.ToLower(v[at+1:])
	if !mailHost(v[:at], host) {
		return false
	}
	if fileHost(host) || docFiles[host] || !mailTLD(host[strings.LastIndexByte(host, '.')+1:]) {
		return false
	}
	if exampleHost(host) {
		return false
	}
	return !strings.HasPrefix(host, "noreply") && !strings.Contains(v, "noreply@")
}

// exampleHost says host, in lower case, is kept for examples and tests
// (RFC 2606): example.com, anything.test, localhost.
func exampleHost(host string) bool {
	for _, fake := range []string{"example.com", "example.org", "example.net", "localhost", ".test", ".invalid", ".example", ".localhost"} {
		if host == strings.TrimPrefix(fake, ".") || strings.HasSuffix(host, fake) {
			return true
		}
	}
	return false
}

// mailHost is whether host can be a mail domain, and not a linker's table
// (system@plt, memcpy@GLIBC_2.14).
func mailHost(local, host string) bool {
	if strings.HasSuffix(local, "@") || !strings.Contains(host, ".") || strings.Trim(host, ".") != host {
		return false
	}
	linker := true
	for _, l := range strings.Split(host, ".") {
		if l == "" || strings.ContainsFunc(l, func(r rune) bool { return r < 0x80 && r != '-' && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') }) {
			return false
		}
		if !linkerWords[l] {
			linker = false
		}
	}
	return !linker
}

var linkerWords = map[string]bool{"plt": true, "got": true, "sec": true, "iplt": true, "igot": true}

// docFiles are the files agents read by name, which end like a domain.
var docFiles = map[string]bool{
	"agents.md": true, "claude.md": true, "gemini.md": true, "readme.md": true, "skill.md": true,
	"changelog.md": true, "contributing.md": true, "license.md": true, "lessons.md": true, "todo.md": true,
	"copilot-instructions.md": true, "crush.md": true, "qwen.md": true, "iflow.md": true, "warp.md": true,
}

// localTLDs are names an organisation's own mail can end in that no
// registry has.
var localTLDs = map[string]bool{"local": true, "internal": true, "lan": true, "corp": true, "home": true, "intranet": true, "localdomain": true}

// mailTLD is whether tld is one mail can be sent to: in the public suffix
// list's ICANN part, or an organisation's own.
func mailTLD(tld string) bool {
	if localTLDs[tld] {
		return true
	}
	_, icann := publicsuffix.PublicSuffix(tld)
	return icann
}

// fileExt are file name extensions that are no top-level domain.
var fileExt = map[string]bool{
	"jpg": true, "jpeg": true, "png": true, "gif": true, "webp": true, "svg": true, "heic": true, "heif": true,
	"avif": true, "bmp": true, "tif": true, "tiff": true, "ico": true, "icns": true, "pdf": true,
	"svgz": true, "apng": true, "jxl": true, "psd": true, "eps": true, "lottie": true,
	"mp4": true, "m4v": true, "webm": true, "mkv": true, "avi": true, "mp3": true, "m4a": true, "wav": true,
	"ogg": true, "flac": true, "aac": true, "ttf": true, "otf": true, "woff": true, "woff2": true, "eot": true,
	"json": true, "yaml": true, "yml": true, "toml": true, "xml": true, "txt": true, "csv": true, "tsv": true,
	"log": true, "html": true, "htm": true, "css": true, "scss": true, "less": true, "js": true, "mjs": true,
	"cjs": true, "jsx": true, "ts": true, "tsx": true, "doc": true, "docx": true, "xls": true, "xlsx": true,
	"ppt": true, "pptx": true, "gz": true, "tgz": true, "tar": true, "rar": true, "7z": true, "dmg": true,
}

// scaleExt are file extensions that are top-level domains too: a name
// ending in one is a file's only with a scale before it, icon@2x.zip.
var scaleExt = map[string]bool{"zip": true, "mov": true, "md": true, "map": true}

var scaleRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)?x$`)

func fileHost(host string) bool {
	dot := strings.LastIndexByte(host, '.')
	ext := host[dot+1:]
	return fileExt[ext] || dot > 0 && scaleExt[ext] && scaleRe.MatchString(host[:dot])
}

// chineseID checks a mainland ID number's check digit.
func chineseID(v string) bool {
	w := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(v[i]-'0') * w[i]
	}
	return strings.ToUpper(v[17:]) == string("10X98765432"[sum%11])
}

// luhn checks a card number of 15 to 19 digits.
func luhn(v string) bool {
	var ds []int
	for _, r := range v {
		if r >= '0' && r <= '9' {
			ds = append(ds, int(r-'0'))
		}
	}
	if len(ds) < 15 || len(ds) > 19 {
		return false
	}
	sum := 0
	for i := range ds {
		d := ds[len(ds)-1-i]
		if i%2 == 1 {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
