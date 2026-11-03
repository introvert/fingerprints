package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := &Record{Summary: Summary{IP: "1.2.3.4", JA4: "t13d", BrowserHash: "bh1", CombinedHash: "c1"}, Report: json.RawMessage(`{"x":1}`)}
	b := &Record{Summary: Summary{IP: "1.2.3.4", JA4: "t13d", BrowserHash: "bh1", CombinedHash: "c2"}, Report: json.RawMessage(`{"x":2}`)}
	for _, r := range []*Record{a, b} {
		if err := s.Insert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Get(ctx, a.ID)
	if err != nil || string(got.Report) != `{"x":1}` || got.IP != "1.2.3.4" {
		t.Fatalf("get: %v %+v", err, got)
	}
	list, _ := s.List(ctx, Filter{BrowserHash: "bh1"})
	if len(list) != 2 {
		t.Fatalf("list = %d", len(list))
	}
	rel, _ := s.Related(ctx, &a.Summary, 10)
	if len(rel["browser_hash"]) != 1 || rel["browser_hash"][0].ID != b.ID || len(rel["combined_hash"]) != 0 {
		t.Fatalf("related = %+v", rel)
	}
	if err := s.Delete(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, a.ID); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
}

func TestPaginationSameMillisecond(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "fp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	for i := 0; i < 7; i++ { // all in the same millisecond
		s.Insert(ctx, &Record{Summary: Summary{CreatedAt: now}, Report: json.RawMessage(`{}`)})
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		list, err := s.List(ctx, Filter{Limit: 3, BeforeID: cursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range list {
			if seen[r.ID] {
				t.Fatalf("duplicate %s", r.ID)
			}
			seen[r.ID] = true
		}
		if len(list) < 3 {
			break
		}
		cursor = list[len(list)-1].ID
	}
	if len(seen) != 7 {
		t.Fatalf("paginated %d of 7 records", len(seen))
	}
}
