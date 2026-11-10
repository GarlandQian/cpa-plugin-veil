package roundtrip

import (
	"fmt"
	"testing"

	"github.com/GarlandQian/cpa-plugin-veil/internal/records"
)

// The links are kept in two generations. A link put again after a generation
// has turned must not leave its older copy to be taken a second time.
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
