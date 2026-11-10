package main

import (
	"fmt"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
)

func TestRecordLinksScopeRequestIDsAndConsumeOnce(t *testing.T) {
	links := newRecordLinks()
	for n, scope := range []string{"caller-a", "caller-b"} {
		links.put(scope, "same-id", records.Ref{Key: int64(n + 1)})
		// A no-op after-auth hook must not overwrite a recorded before-auth hook.
		links.put(scope, "same-id", records.Ref{})
	}
	if _, ok := links.take("caller-c", "same-id"); ok {
		t.Fatal("another caller took the record")
	}
	for n, scope := range []string{"caller-a", "caller-b"} {
		if got, ok := links.take(scope, "same-id"); !ok || got.Key != int64(n+1) {
			t.Fatalf("%s: %v, %t", scope, got, ok)
		}
		if _, ok := links.take(scope, "same-id"); ok {
			t.Fatal("a repeated response took the record twice")
		}
	}
}

func TestRecordLinkUpdateCannotLeaveAStaleGeneration(t *testing.T) {
	links := newRecordLinks()
	links.put("caller", "updated", records.Ref{Key: 1})
	for n := 0; n < recordLinksGenSize; n++ {
		links.put("caller", fmt.Sprint(n), records.Ref{Key: int64(n + 2)})
	}
	links.put("caller", "updated", records.Ref{Key: 99999})
	if got, ok := links.take("caller", "updated"); !ok || got.Key != 99999 {
		t.Fatalf("update lost: %v, %t", got, ok)
	}
	if _, ok := links.take("caller", "updated"); ok {
		t.Fatal("a repeated response consumed the stale association")
	}
}

// A call that names no request has no record: nothing else says which
// request it is about.
func TestRecordLinksNeedARequestID(t *testing.T) {
	links := newRecordLinks()
	links.put("caller", "", records.Ref{Key: 1})
	if _, ok := links.take("caller", ""); ok {
		t.Fatal("a call without a request ID took a record")
	}
}
