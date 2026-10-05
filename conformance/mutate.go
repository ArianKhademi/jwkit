package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

// Differential testing.
//
// fixtures.json holds cases somebody thought of, each with a known answer.
// This file produces cases nobody thought of, with no known answer: tokens
// mutated at random, many of them re-signed with the issuer's real key so
// that they get past the signature check and into header and claim handling.
// Both runners verify them and their outputs are diffed. There is nothing to
// compare against except each other, which is the point: the property under
// test is that Go and TypeScript agree on every input, including on which
// typed error a broken token gets.
//
// The output has the same schema as fixtures.json with an empty `expect`,
// which the runners take to mean "record the result, expect nothing".
//
// A run is fully determined by its seed, so a disagreement found in CI can be
// replayed locally with `make differential SEED=<seed>`.

func writeMutations(path string, keys *keyring, n int, seed uint64) error {
	m := &mutator{
		r:    rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		keys: keys,
	}
	for _, c := range buildCases(keys) {
		// The 64 KiB case only ever exercises the size check.
		if len(c.Token) <= 2*maxTokenBytes {
			m.base = append(m.base, c.Token)
		}
	}

	cases := make([]Case, 0, n)
	for i := 0; i < n; i++ {
		strategy, token := m.next()
		cases = append(cases, Case{
			Name:  fmt.Sprintf("seed%d-%05d-%s", seed, i, strategy),
			About: "Randomly generated; see conformance/mutate.go.",
			Token: token,
		})
	}

	fx := Fixtures{
		Description: fmt.Sprintf("Differential test input: %d random mutations, seed %d. No expectations; the two runners' results are compared with each other.", n, seed),
		Config:      Config{Issuer: issuer, Audience: audience, Now: now, ClockSkewSec: clockSkewSec, MaxTokenBytes: maxTokenBytes},
		JWKS:        keys.jwks(),
		Cases:       cases,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fx); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d mutations, seed %d\n", path, n, seed)
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

type mutator struct {
	r    *rand.Rand
	keys *keyring
	base []string // fixture tokens to mutate
}

func (m *mutator) pick(options ...string) string { return options[m.r.IntN(len(options))] }

func (m *mutator) chance(percent int) bool { return m.r.IntN(100) < percent }

// signer returns one of the keys the issuer really signs with.
func (m *mutator) signer() *key {
	if m.chance(70) {
		return m.keys.rsaCurrent
	}
	return m.keys.ecCurrent
}

func (m *mutator) next() (strategy, token string) {
	switch m.r.IntN(10) {
	case 0, 1:
		return "chars", m.editChars(m.pick(m.base...))
	case 2:
		return "segments", m.mixSegments()
	case 3:
		// A valid header whose JSON text has been damaged, then signed.
		k := m.signer()
		return "header-text", k.signed(m.editJSONText(toJSON(k.header())), toJSON(claims()))
	case 4, 5:
		// Valid claims whose JSON text has been damaged, then signed.
		k := m.signer()
		return "payload-text", k.signed(toJSON(k.header()), m.editJSONText(toJSON(claims())))
	case 6:
		k := m.signer()
		return "header-gen", k.signed(m.genHeader(k), toJSON(claims()))
	default:
		k := m.signer()
		return "payload-gen", k.signed(toJSON(obj{"alg": k.alg(), "kid": k.kid}), m.genPayload())
	}
}

// editChars applies a few character-level edits to a compact token. The
// result stays valid Unicode so it survives the trip through JSON.
func (m *mutator) editChars(token string) string {
	const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	other := []string{".", "=", "+", "/", " ", "\n", "\r", "\t", "\x00", "é", "%", "\"", "\\"}
	char := func() string {
		if m.chance(80) {
			return string(b64url[m.r.IntN(len(b64url))])
		}
		return m.pick(other...)
	}
	runes := []rune(token)
	for edits := 1 + m.r.IntN(3); edits > 0; edits-- {
		if len(runes) == 0 {
			runes = []rune(char())
			continue
		}
		i := m.r.IntN(len(runes))
		switch m.r.IntN(6) {
		case 0, 1: // replace
			runes = append(runes[:i:i], append([]rune(char()), runes[i+1:]...)...)
		case 2: // insert
			runes = append(runes[:i:i], append([]rune(char()), runes[i:]...)...)
		case 3: // delete
			runes = append(runes[:i:i], runes[i+1:]...)
		case 4: // truncate
			runes = runes[:i]
		case 5: // swap two neighbours
			if i+1 < len(runes) {
				runes[i], runes[i+1] = runes[i+1], runes[i]
			}
		}
	}
	return string(runes)
}

// mixSegments builds a token out of segments taken from different fixtures.
func (m *mutator) mixSegments() string {
	var segments []string
	for _, t := range m.base {
		segments = append(segments, strings.Split(t, ".")...)
	}
	n := 3
	if m.chance(15) {
		n = 1 + m.r.IntN(5)
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = m.pick(segments...)
	}
	return strings.Join(parts, ".")
}

// editJSONText damages JSON at the byte level: the edits come from an
// alphabet of JSON syntax and of the escapes and literals parsers differ on.
func (m *mutator) editJSONText(text string) string {
	fragments := []string{
		"{", "}", "[", "]", ",", ":", "\"", "\\", " ", "\n", "\t", "0", "1", "9", "-", "+", ".", "e", "E",
		"null", "true", "false", "NaN", "Infinity", "1e400", "-1e400", "1e-400", "0x10", "01", "1.", ".5",
		`\u0000`, `\ud800`, `\udc00`, `\ud83d\ude00`, `\x41`, `\/`, `\'`, "'", "//", "/**/",
		"\x00", "\x1f", "\x7f", "\xff", "\xc3\x28", "\xef\xbb\xbf", "\xe2\x80\xa8", "é", "\u00a0",
		`"exp":0,`, `"exp":1e400,`, `"iss":null,`, `"aud":[],`, `"alg":"none",`, `"crit":[],`, `"kid":"",`,
	}
	b := []byte(text)
	for edits := 1 + m.r.IntN(3); edits > 0; edits-- {
		i := m.r.IntN(len(b) + 1)
		frag := []byte(m.pick(fragments...))
		switch m.r.IntN(5) {
		case 0, 1: // insert
			b = append(b[:i:i], append(frag, b[i:]...)...)
		case 2: // overwrite
			end := min(i+len(frag), len(b))
			b = append(b[:i:i], append(frag, b[end:]...)...)
		case 3: // delete a short run
			end := min(i+1+m.r.IntN(4), len(b))
			b = append(b[:i:i], b[end:]...)
		case 4: // truncate
			b = b[:i]
		}
	}
	return string(b)
}

func (m *mutator) number() string {
	n := int64(now)
	return m.pick(
		// Around every boundary the time checks have.
		fmt.Sprint(n-61), fmt.Sprint(n-60), fmt.Sprint(n-59), fmt.Sprint(n), fmt.Sprint(n+59), fmt.Sprint(n+60), fmt.Sprint(n+61),
		fmt.Sprint(n+3600), fmt.Sprintf("%d.5", n-60), fmt.Sprintf("%d.999", n-61), fmt.Sprintf("%d.0", n+60), fmt.Sprintf("%de0", n+61),
		// Ordinary and extreme values.
		"0", "-0", "1", "-1", "1.5", "1E5", "0.1e1", "1e308", "1e309", "1e400", "-1e400", "1e-400", "4.9e-324",
		"1.7976931348623157e308", "1.7976931348623159e308", "9007199254740993", "123456789012345678901234567890",
		// Not numbers at all.
		"01", "1.", ".5", "+1", "0x10", "NaN", "Infinity", "-", "1e", "--1",
	)
}

func (m *mutator) str() string {
	return m.pick(
		`"`+issuer+`"`, `"`+audience+`"`, `"`+issuer+`/"`, `"https://evil.example"`, `""`, `"user-123"`,
		`"`+m.keys.rsaCurrent.kid+`"`, `"`+m.keys.ecCurrent.kid+`"`, `"`+m.keys.rsaWeak.kid+`"`, `"`+m.keys.rsaEnc.kid+`"`, `"no-such-key"`,
		`"\u0000"`, `"\ud800"`, `"\ud83d\ude00"`, `"é"`, `"a\"b"`, `"a\/b"`, `"\x41"`, "\"\x01\"", "\"\xff\"", `"unterminated`,
		`"read write"`, `"1750003600"`,
	)
}

func (m *mutator) value(depth int) string {
	switch m.r.IntN(12) {
	case 0:
		return "null"
	case 1:
		return m.pick("true", "false")
	case 2, 3, 4:
		return m.number()
	case 5, 6, 7:
		return m.str()
	case 8, 9:
		if depth <= 0 {
			return "[]"
		}
		items := make([]string, m.r.IntN(4))
		for i := range items {
			items[i] = m.value(depth - 1)
		}
		return "[" + strings.Join(items, ",") + "]"
	default:
		if depth <= 0 {
			return "{}"
		}
		return m.object(depth-1, []string{`"a"`, `"b"`, `"iss"`, `"exp"`, `"__proto__"`})
	}
}

func (m *mutator) object(depth int, names []string) string {
	members := make([]string, m.r.IntN(5))
	for i := range members {
		members[i] = m.pick(names...) + ":" + m.value(depth)
	}
	return "{" + strings.Join(members, ",") + "}"
}

// wrap occasionally surrounds JSON with whitespace or trailing junk.
func (m *mutator) wrap(text string) string {
	if m.chance(90) {
		return text
	}
	return m.pick("", " ", "\n", "\t", "\xef\xbb\xbf", "\x00") + text + m.pick("", " ", "\n", "}", "{}", ",", "null", "\x00")
}

// genHeader builds a header member by member. Each member is usually what a
// real token would carry and sometimes anything at all, so most results reach
// the later checks instead of all dying on the first.
func (m *mutator) genHeader(k *key) string {
	var members []string
	add := func(name string, percent int, usual func() string) {
		if !m.chance(percent) {
			return
		}
		v := usual()
		if m.chance(20) {
			v = m.value(2)
		}
		members = append(members, name+":"+v)
	}
	add(`"alg"`, 95, func() string {
		return m.pick(`"`+k.alg()+`"`, `"`+k.alg()+`"`, `"`+k.alg()+`"`, `"RS256"`, `"ES256"`, `"none"`, `"HS256"`, `"RS384"`, `"PS256"`, `"rs256"`, `""`)
	})
	add(`"kid"`, 95, func() string {
		return m.pick(`"`+k.kid+`"`, `"`+k.kid+`"`, `"`+k.kid+`"`, `"`+m.keys.rsaCurrent.kid+`"`, `"`+m.keys.ecCurrent.kid+`"`,
			`"`+m.keys.rsaWeak.kid+`"`, `"`+m.keys.ecP384.kid+`"`, `"`+m.keys.rsaEnc.kid+`"`, `"`+m.keys.rsaPS256.kid+`"`, `"no-such-key"`, `""`)
	})
	add(`"typ"`, 50, func() string { return m.pick(`"JWT"`, `"at+jwt"`) })
	add(`"crit"`, 5, func() string { return m.pick(`[]`, `["exp"]`, `["b64"]`) })
	add(`"b64"`, 5, func() string { return "false" })
	add(`"jku"`, 10, func() string { return `"https://attacker.example/jwks.json"` })
	add(`"x5u"`, 5, func() string { return `"https://attacker.example/cert.pem"` })
	add(`"jwk"`, 10, func() string {
		return m.pick(toJSON(m.keys.rsaAttacker.publicJWK()), `"garbage"`, `{}`, `{"kty":"oct","k":"AAAA"}`)
	})
	add(`"x5c"`, 5, func() string { return m.pick(`[]`, `["not a certificate"]`, `7`) })
	add(`"ALG"`, 5, func() string { return `"RS256"` })
	add(`"__proto__"`, 5, func() string { return `{"alg":"` + k.alg() + `","kid":"` + k.kid + `"}` })
	// Member order matters when names repeat, so shuffle and sometimes repeat one.
	m.r.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
	if len(members) > 0 && m.chance(10) {
		members = append(members, members[m.r.IntN(len(members))])
	}
	return m.wrap("{" + strings.Join(members, ",") + "}")
}

func (m *mutator) genPayload() string {
	var members []string
	add := func(name string, percent int, usual func() string) {
		if !m.chance(percent) {
			return
		}
		v := usual()
		if m.chance(15) {
			v = m.value(2)
		}
		members = append(members, name+":"+v)
	}
	add(`"iss"`, 95, func() string { return `"` + issuer + `"` })
	add(`"aud"`, 95, func() string {
		return m.pick(`"`+audience+`"`, `"`+audience+`"`, `["`+audience+`"]`, `["x","`+audience+`"]`, `[7,null,"`+audience+`"]`, `[]`, `["x"]`)
	})
	add(`"exp"`, 95, func() string {
		if m.chance(70) {
			return fmt.Sprint(now + 3600)
		}
		return m.number()
	})
	add(`"nbf"`, 40, m.number)
	add(`"iat"`, 40, m.number)
	add(`"sub"`, 50, m.str)
	add(`"scope"`, 20, m.str)
	add(`"__proto__"`, 5, func() string { return fmt.Sprintf(`{"iss":%q,"aud":%q,"exp":%d}`, issuer, audience, now+3600) })
	add(`"constructor"`, 5, func() string { return m.value(1) })
	add(`"x"`, 30, func() string { return m.value(3) })
	m.r.Shuffle(len(members), func(i, j int) { members[i], members[j] = members[j], members[i] })
	if len(members) > 0 && m.chance(10) {
		members = append(members, members[m.r.IntN(len(members))])
	}
	return m.wrap("{" + strings.Join(members, ",") + "}")
}
