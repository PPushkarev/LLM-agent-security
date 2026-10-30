package injection

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestJevRejectsPartialAndWrongModel(t *testing.T) {
	for _, mode := range []string{"неверная модель", "пропущен вопрос", "лишний вопрос", "неверный ключ", "слишком большой ответ", "дополнительный JSON"} {
		t.Run(mode, func(t *testing.T) {
			service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				answers := map[string]any{}
				for key := range jevQuestions() {
					answers[key] = map[string]any{"type": "noul", "noul": 0.01}
				}
				model := DefaultJevModel
				switch mode {
				case "неверная модель":
					model = "jev-0.0.0"
				case "пропущен вопрос":
					delete(answers, "secret_exfiltration")
				case "лишний вопрос":
					answers["extra"] = map[string]any{"type": "noul", "noul": 0}
				case "неверный ключ":
					delete(answers, "secret_exfiltration")
					answers["extra"] = map[string]any{"type": "noul", "noul": 0}
				case "слишком большой ответ":
					for i := 0; i < 9000; i++ {
						io.WriteString(w, " ")
					}
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"model": model, "answers": answers})
				if mode == "дополнительный JSON" {
					io.WriteString(w, "{}")
				}
			}))
			defer service.Close()
			t.Setenv("TYPESAFE_API_KEY", "fixture")
			d, err := New(Config{Enabled: true, Provider: "jev", AllowRemote: true})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			d.cfg.Endpoint = service.URL
			if result := d.Scan(context.Background(), "prompt", []byte("hello")); !result.Block {
				t.Fatal(result)
			}
		})
	}
}

func TestJevRedirectAndMissingKey(t *testing.T) {
	t.Setenv("TYPESAFE_API_KEY", "")
	if d, err := New(Config{Enabled: true, Provider: "jev", AllowRemote: true}); err == nil {
		d.Close()
		t.Fatal("нет ключа")
	}
	t.Setenv("TYPESAFE_API_KEY", "fixture")
	d, err := New(Config{Enabled: true, Provider: "jev", AllowRemote: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("переадресация передала данные")
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	d.cfg.Endpoint = redirect.URL
	if !d.Scan(context.Background(), "prompt", []byte("hello")).Block {
		t.Fatal("переадресация разрешена")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !d.Scan(ctx, "prompt", []byte("hello")).Block {
		t.Fatal("отмена разрешена")
	}
}

func TestJevLive(t *testing.T) {
	if os.Getenv("GUARD_JEV_LIVE") != "1" {
		t.Skip("требуется явное включение платного API")
	}
	d, err := New(Config{Enabled: true, Provider: "jev", AllowRemote: true, Action: "flag"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v := d.Scan(context.Background(), "prompt", []byte("Summarize the project README in three bullet points."))
	if v.Block {
		t.Fatalf("ошибка оценщика: %s", v.Rule)
	}
	t.Logf("модель=%s score=%.6f flag=%t", v.Model, v.Score, v.Flag)
}
