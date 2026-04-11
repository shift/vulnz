package pbt

import (
	"testing"

	"github.com/shift/vulnz/internal/utils/rpm"
	"pgregory.net/rapid"
)

func TestRPMCompareReflexivity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapidRPMVersion().Draw(t, "v")
		if v == nil {
			return
		}
		result := v.Compare(v)
		assert(t, result == 0, "reflexivity: v.Compare(v) != 0")
	})
}

func TestRPMCompareAntisymmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v1 := rapidRPMVersion().Draw(t, "v1")
		v2 := rapidRPMVersion().Draw(t, "v2")
		if v1 == nil || v2 == nil {
			return
		}

		ab := v1.Compare(v2)
		ba := v2.Compare(v1)

		if ab == 0 {
			assert(t, ba == 0, "antisymmetry: a==b but b!=a")
		} else {
			assert(t, ab == -ba, "antisymmetry: compare(a,b) != -compare(b,a)")
		}
	})
}

func TestRPMCompareTransitivity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v1 := rapidRPMVersion().Draw(t, "v1")
		v2 := rapidRPMVersion().Draw(t, "v2")
		v3 := rapidRPMVersion().Draw(t, "v3")
		if v1 == nil || v2 == nil || v3 == nil {
			return
		}

		cmp12 := v1.Compare(v2)
		cmp23 := v2.Compare(v3)

		if cmp12 > 0 && cmp23 > 0 {
			cmp13 := v1.Compare(v3)
			assert(t, cmp13 > 0, "transitivity: a>b and b>c but a<=c")
		}
		if cmp12 < 0 && cmp23 < 0 {
			cmp13 := v1.Compare(v3)
			assert(t, cmp13 < 0, "transitivity: a<b and b<c but a>=c")
		}
	})
}

func TestRPMCompareIdempotency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v1 := rapidRPMVersion().Draw(t, "v1")
		v2 := rapidRPMVersion().Draw(t, "v2")
		if v1 == nil || v2 == nil {
			return
		}

		r1 := v1.Compare(v2)
		r2 := v1.Compare(v2)
		assert(t, r1 == r2, "idempotency: compare not deterministic")
	})
}

func TestRPMParseNeverPanic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapidVersionString().Draw(t, "v")
		_, _ = rpm.Parse(v)
	})
}

func TestRPMCompareKnownCases(t *testing.T) {
	tests := []struct {
		v1, v2 string
		want   int
	}{
		{"1.2.3", "1.2.4", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0", 0},
		{"2:1.0-1", "1:9999-999", 1},
		{"1a", "1b", -1},
		{"2.0.0", "1.9.9", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0-1.el8", "1.0-2.el8", -1},
	}

	for _, tc := range tests {
		v1, err1 := rpm.Parse(tc.v1)
		v2, err2 := rpm.Parse(tc.v2)
		if err1 != nil || err2 != nil {
			continue
		}
		got := v1.Compare(v2)
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.v1, tc.v2, got, tc.want)
		}
	}
}

func TestRPMParseRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		epoch := rapid.IntRange(0, 10).Draw(t, "epoch")
		ver := rapid.StringMatching("[0-9]+(\\.[0-9]+)*").Draw(t, "ver")
		release := rapid.StringMatching("[0-9]+(\\.[a-z0-9]+)*").Draw(t, "release")

		if ver == "" {
			ver = "1.0"
		}

		v, err := rpm.New(epoch, ver, release)
		assert(t, err == nil, "rpm.New failed")

		str := v.String()
		parsed, err := rpm.Parse(str)
		assert(t, err == nil, "Parse failed on roundtrip")
		assert(t, parsed.Compare(v) == 0, "Parse roundtrip mismatch")
	})
}

func rapidRPMVersion() *rapid.Generator[*rpm.Version] {
	return rapid.Custom(func(t *rapid.T) *rpm.Version {
		s := rapidVersionString().Draw(t, "s")
		v, _ := rpm.Parse(s)
		return v
	})
}

func rapidVersionString() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		runes := make([]rune, rapid.IntRange(0, 30).Draw(t, "len"))
		for i := range runes {
			runes[i] = rapid.Rune().Draw(t, "r")
		}
		return string(runes)
	})
}
