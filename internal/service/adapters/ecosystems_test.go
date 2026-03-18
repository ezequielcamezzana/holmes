package adapters

import (
	"encoding/json"
	"testing"
)

func TestParseAdvisoryReferences_StringArray(t *testing.T) {
	raw := json.RawMessage(`[
	  "https://github.com/advisories/GHSA-wf5p-g6vw-rhxx",
	  "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"
	]`)

	refs := parseAdvisoryReferenceURLs(raw)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs[0] == "" || refs[1] == "" {
		t.Fatal("expected non-empty urls")
	}
}

func TestParseAdvisoryReferences_ObjectArray(t *testing.T) {
	raw := json.RawMessage(`[
	  {"type":"ADVISORY","url":"https://example.com/a"},
	  {"type":"REPORT","url":"https://example.com/b"}
	]`)

	refs := parseAdvisoryReferenceURLs(raw)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs[0] != "https://example.com/a" {
		t.Fatalf("unexpected first url %q", refs[0])
	}
}
