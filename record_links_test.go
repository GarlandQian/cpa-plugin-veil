package main

import (
	"fmt"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
)

func TestRecordLinksScopeRequestIDsAndConsumeOnce(t *testing.T) {
	links := newRecordLinks()
	body := []byte("identical body")
	for n, scope := range []string{"caller-a", "caller-b"} {
		links.put(scope, "same-id", bodySum(scope, body), records.Ref{Key: int64(n + 1)})
		// A no-op after-auth hook must not overwrite a recorded before-auth hook.
		links.put(scope, "same-id", bodySum(scope, body), records.Ref{})
	}
	if _, ok := links.take("caller-c", "same-id", body); ok {
		t.Fatal("another caller took the record")
	}
	for n, scope := range []string{"caller-a", "caller-b"} {
		if got, ok := links.take(scope, "same-id", []byte("translated body")); !ok || got.Key != int64(n+1) {
			t.Fatalf("%s: %v, %t", scope, got, ok)
		}
		if _, ok := links.take(scope, "same-id", body); ok {
			t.Fatal("a repeated response took the record twice")
		}
	}
}

func TestRecordLinkUpdateCannotLeaveAStaleGeneration(t *testing.T) {
	links := newRecordLinks()
	body := bodySum("caller", []byte("body"))
	links.put("caller", "updated", body, records.Ref{Key: 1})
	for n := 0; n < recordLinksGenSize; n++ {
		links.put("caller", fmt.Sprint(n), body, records.Ref{Key: int64(n + 2)})
	}
	links.put("caller", "updated", body, records.Ref{Key: 99999})
	if got, ok := links.take("caller", "updated"); !ok || got.Key != 99999 {
		t.Fatalf("update lost: %v, %t", got, ok)
	}
	if _, ok := links.take("caller", "updated"); ok {
		t.Fatal("a repeated response consumed the stale association")
	}
}

func TestLegacyRecordCandidatesMustBeUnambiguous(t *testing.T) {
	links := newRecordLinks()
	raw, translated := []byte("raw body"), []byte("translated body")
	links.put("caller", "", bodySum("caller", raw), records.Ref{Key: 1})
	links.put("caller", "", bodySum("caller", translated), records.Ref{Key: 2})
	if _, ok := links.take("caller", "", raw, translated); ok {
		t.Fatal("two matching bodies picked an arbitrary record")
	}
	for _, body := range [][]byte{raw, translated} {
		links.put("caller", "", bodySum("caller", body), records.Ref{Key: 3})
		if _, ok := links.take("caller", "", body); ok {
			t.Fatal("an ambiguous body associated a newer record")
		}
	}
	// A collision in one scope does not disable another caller's statistics.
	links.put("other", "", bodySum("other", raw), records.Ref{Key: 4})
	if got, ok := links.take("other", "", raw, raw); !ok || got.Key != 4 {
		t.Fatalf("duplicate candidate or other caller affected a unique match: %v, %t", got, ok)
	}
}

func TestLegacyRecordCacheSaturationCannotReassignALateResponse(t *testing.T) {
	links := newRecordLinks()
	old := []byte("0")
	for n := 0; n <= 2*recordLinksGenSize; n++ {
		body := []byte(fmt.Sprint(n))
		links.put("caller", "", bodySum("caller", body), records.Ref{Key: int64(n + 1)})
	}
	links.put("caller", "", bodySum("caller", old), records.Ref{Key: 99999})
	if _, ok := links.take("caller", "", old); ok {
		t.Fatal("evicting an old pending body allowed its late response to take a new record")
	}
	fresh := []byte("fresh")
	links.put("caller", "", bodySum("caller", fresh), records.Ref{Key: 100000})
	if _, ok := links.take("caller", "", fresh); ok {
		t.Fatal("saturated legacy cache resumed unsafe correlation")
	}
	links.put("caller", "known-id", bodySum("caller", old), records.Ref{Key: 100001})
	if got, ok := links.take("caller", "known-id"); !ok || got.Key != 100001 {
		t.Fatalf("legacy saturation affected ID correlation: %v, %t", got, ok)
	}
}
