package pbt

import "pgregory.net/rapid"

func assert(t *rapid.T, cond bool, msg string) {
	if !cond {
		t.Errorf("%s", msg)
	}
}
