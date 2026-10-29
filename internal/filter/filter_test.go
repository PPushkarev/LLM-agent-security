package filter

import (
	"net/url"
	"testing"
)

func TestURLRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, path, query, mode string
		action                  Action
		want                    string
	}{
		{"encoded", "/search", "q=%73ensitive", "", Redact, "[REDACTED:secret]"},
		{"repeated", "/search", "q=sensitive&q=%73ensitive", "", Redact, "[REDACTED:secret]"},
		{"path", "/sensitive", "q=clean", "", Block, ""},
		{"monitor", "/search", "q=%73ensitive", "monitor", Allow, ""},
		{"malformed", "/search", "q=%zz", "", Block, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := New(Config{Enabled: true, Mode: tc.mode, Redact: []Rule{{Name: "secret", Pattern: "sensitive", Action: "redact"}}})
			if err != nil {
				t.Fatal(err)
			}
			out, d := f.URL(tc.path, tc.query)
			if d.Action != tc.action {
				t.Fatalf("action=%v want %v", d.Action, tc.action)
			}
			if tc.mode == "monitor" && out != tc.query {
				t.Fatalf("monitor changed query: %q", out)
			}
			if tc.action == Redact {
				v, err := url.ParseQuery(out)
				if err != nil {
					t.Fatal(err)
				}
				for _, q := range v["q"] {
					if q != tc.want {
						t.Fatalf("unredacted value %q", q)
					}
				}
			}
		})
	}
}
