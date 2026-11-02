package detect

import (
	"strings"
	"testing"
	"time"
)

func kindsIn(t *testing.T, d *Detector, text string) []string {
	t.Helper()
	var out []string
	for _, h := range d.Detect(text) {
		out = append(out, string(h.Kind)+"="+text[h.Start:h.End])
	}
	return out
}

func mustNew(t *testing.T, opts Options) *Detector {
	t.Helper()
	d, err := New(nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCategoriesFindTheirKinds(t *testing.T) {
	saved := dateClock
	dateClock = func() time.Time { return time.Date(2026, 11, 3, 0, 0, 0, 0, time.Local) }
	t.Cleanup(func() { dateClock = saved })

	all := map[string]bool{"home": true, "userhost": true, "ip": true, "bucket": true}
	cases := []struct {
		cat, text, want string
	}{
		{"secrets", "密码是 Qwer1234x", "PASSWORD=Qwer1234x"},
		{"secrets", "DATABASE_URL=postgres://app:hunter2pass@db.acme-corp.cn/x", "PASSWORD=hunter2pass"},
		{"secrets", "export SERVICE_X_KEY=Ab12Cd34Ef56Gh78", "SECRET=Ab12Cd34Ef56Gh78"},
		{"secrets", "Authorization: Bearer s3cr3t-0paque-t0ken", "SECRET=Bearer s3cr3t-0paque-t0ken"},
		{"secrets", "令牌是 9f8e7d6c5b4a", "SECRET=9f8e7d6c5b4a"},
		{"secrets", "key AIzaSyD-1234567890abcdefghijklmnop_qrst in config", "SECRET=AIzaSyD-1234567890abcdefghijklmnop_qrst"},
		{"secrets", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"},
		{"personal", "mail alice@acme-corp.cn", "EMAIL=alice@acme-corp.cn"},
		{"personal", "我的手机号是 13800138000", "PHONE=13800138000"},
		{"personal", "身份证 110105199003077438", "ID_CARD=110105199003077438"},
		{"personal", "card 4111 1111 1111 1111", "BANK_CARD=4111 1111 1111 1111"},
		{"ssn", "SSN: 536-90-4399", "SSN=536-90-4399"},
		{"passport", "Passport No.: E12345678", "PASSPORT=E12345678"},
		{"iban", "IBAN DE89370400440532013000", "IBAN=DE89370400440532013000"},
		{"birthday", "生日：1990-03-07", "BIRTHDAY=1990-03-07"},
		{"mac", "ether a4:5e:60:c1:2b:3d", "MAC=a4:5e:60:c1:2b:3d"},
		{"serial", "S/N: AB12CD34EF", "SERIAL=AB12CD34EF"},
		{"home", "open /Users/garland/project/main.go", "USERNAME=garland"},
		{"userhost", "ssh deploy@build-17.acme-corp.cn", "USERNAME=deploy,HOSTNAME=build-17.acme-corp.cn"},
		{"ip", "server 47.100.12.34 is up", "IP=47.100.12.34"},
		{"bucket", "aws s3 cp x s3://acme-prod-logs/2026/", "BUCKET=acme-prod-logs"},
	}
	for _, tc := range cases {
		on := mustNew(t, Options{Categories: all})
		if got := strings.Join(kindsIn(t, on, tc.text), ","); got != tc.want {
			t.Errorf("[%s] %q: got %q, want %q", tc.cat, tc.text, got, tc.want)
		}
		off := mustNew(t, Options{Categories: map[string]bool{tc.cat: false}})
		if got := kindsIn(t, off, tc.text); len(got) != 0 {
			t.Errorf("[%s] off still finds %v in %q", tc.cat, got, tc.text)
		}
	}
}

func TestOptionalCategoriesDefaults(t *testing.T) {
	d := mustNew(t, Options{})
	for _, text := range []string{
		"open /Users/garland/project/main.go",
		"ssh deploy@build-17.acme-corp.cn",
		"server 47.100.12.34 is up",
		"aws s3 cp x s3://acme-prod-logs/2026/",
	} {
		if got := kindsIn(t, d, text); len(got) != 0 {
			t.Errorf("an off-by-default category found %v in %q", got, text)
		}
	}
	if got := kindsIn(t, d, "SSN: 536-90-4399"); len(got) != 1 {
		t.Errorf("ssn is on by default, got %v", got)
	}
}

// Shapes that look sensitive and are not, including the false positives
// magpie's users reported.
func TestFalsePositives(t *testing.T) {
	saved := dateClock
	dateClock = func() time.Time { return time.Date(2026, 11, 3, 0, 0, 0, 0, time.Local) }
	t.Cleanup(func() { dateClock = saved })
	d := mustNew(t, Options{Categories: map[string]bool{"home": true, "userhost": true, "ip": true, "bucket": true}})
	for _, text := range []string{
		"created_at 1730000000123 ms",                      // a millisecond timestamp (yetone/magpie#3577)
		`{"timestamp": 17929036837}`,                       // a bare JSON number
		"PMID: 38012345, 37654321, 36998877",               // PubMed ids (yetone/magpie#3631)
		"订单号 13912345678 已发货",                              // an order id
		"lat 31.13800138000",                               // a decimal
		"request 9f13800138000abc0123456789abcdef01",       // a phone's form inside a digest
		"trace 41111111-1111-4111-9111-111111111111",       // a card's form across a UUID
		"uuid 550e8400-e29b-41d4-a716-446655440000",        // a UUID
		"see AGENTS.md@main or user@example.com",           // a doc file and a documentation domain
		"git@github.com:acme/app.git",                      // git's user
		"icon@2x.png and memcpy@GLIBC_2.14",                // a scaled image and a linker symbol
		"Chrome/120.0.6099.109 version 1.2.3.4",            // versions
		"dns 8.8.8.8 and 192.168.1.10",                     // a resolver and a private address
		"生日 2026-10-20",                                    // a date within the last year
		"mac 00:11:22:33:44:55",                            // a documentation MAC
		"token = get_access_token_v2",                      // code naming a secret
		"api_key: ${API_KEY}",                              // a variable
		"see internal/auth/token.go:L643-669.",             // a place in a file
		"jsonwebtoken = \"9.2.0-beta1\"",                   // a package's version
		"js-tokens@4.0.0:",                                 // a pinned package
		"Zm9vYmFyYmF6cXV4cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaA==", // random base64 without any secret word
	} {
		if got := kindsIn(t, d, text); len(got) != 0 {
			t.Errorf("%q: found %v", text, got)
		}
	}
}

func TestEntropyNeedsContext(t *testing.T) {
	d := mustNew(t, Options{})
	blob := "Zm9vYmFyYmF6cXV4cXV1eDEyMzQ1Njc4OTBhYmNkZWZnaA"
	if got := kindsIn(t, d, "token "+blob); len(got) != 1 || !strings.HasPrefix(got[0], "SECRET=") {
		t.Fatalf("with context: %v", got)
	}
	if got := kindsIn(t, d, "blob "+blob); len(got) != 0 {
		t.Fatalf("without context: %v", got)
	}
}

func TestUserOptions(t *testing.T) {
	extra := []byte(`
[[rules]]
id = "internal-ticket"
regex = '''TKT-[0-9]{6}'''
keywords = ["tkt-"]
kind = "TICKET"
`)
	d, err := New(nil, Options{
		Terms:         []Term{{Text: "烛龙"}, {Text: "Phoenix", AnyCase: true, WholeWord: true}},
		Allow:         []string{"ALICE@acme-corp.cn"},
		DisabledRules: []string{"phone-cn"},
		ExtraRules:    extra,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"项目代号烛龙":                         "TERM=烛龙",
		"PHOENIX launches":               "TERM=PHOENIX",
		"phoenixes are not it":           "",
		"mail alice@acme-corp.cn":        "",
		"mail bob@acme-corp.cn":          "EMAIL=bob@acme-corp.cn",
		"我的手机号是 13800138000":             "",
		"see TKT-123456 for the details": "TICKET=TKT-123456",
	}
	for text, want := range cases {
		if got := strings.Join(kindsIn(t, d, text), ","); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
	// The built-in gitleaks rules still load beside the extra ones.
	raw, err := newFromPath(gitleaksRules)
	if err != nil {
		t.Fatal(err)
	}
	builtin, _ := raw.Stats()
	withExtra, err := New(mustRead(t, gitleaksRules), Options{ExtraRules: extra})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := withExtra.Stats(); n != builtin+1 {
		t.Fatalf("extra rules replaced the built-in ones: %d rules, want %d", n, builtin+1)
	}
}

func TestInvalidOptions(t *testing.T) {
	for name, opts := range map[string]Options{
		"unknown category": {Categories: map[string]bool{"cards": true}},
		"unknown rule":     {DisabledRules: []string{"no-such-rule"}},
		"empty term":       {Terms: []Term{{Text: " "}}},
		"lower-case kind":  {ExtraRules: []byte("[[rules]]\nid = \"x\"\nregex = 'x'\nkind = \"ticket\"\n")},
		"bad regex":        {ExtraRules: []byte("[[rules]]\nid = \"x\"\nregex = '(?<=x)y'\n")},
	} {
		if _, err := New(nil, opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSecretField(t *testing.T) {
	for name, want := range map[string]bool{
		"api_key": true, "db_pass": true, "Authorization": true, "client_secret": true, "key": true, "refreshToken": true,
		"max_tokens": false, "sort_key": false, "token_count": false, "name": false,
	} {
		if got := SecretField(name, "abcd1234efgh"); got != want {
			t.Errorf("SecretField(%q) = %v", name, got)
		}
	}
	if SecretField("api_key", "short") || SecretField("api_key", "${API_KEY}") {
		t.Error("a short value or a variable is no secret")
	}
}
