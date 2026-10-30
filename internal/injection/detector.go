// Package injection calls a dedicated local prompt-injection classifier once per
// payload, separately from deterministic PII/secret filtering.
package injection

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type Detector struct {
	cfg       Config
	client    *http.Client
	transport *http.Transport
	token     string
}
type Decision struct {
	Block, Flag       bool
	Rule, Model, Hash string
	Score             float64
}

func New(c Config) (*Detector, error) {
	if !c.Enabled {
		return nil, nil
	}
	if err := Validate(c); err != nil {
		return nil, err
	}
	c = c.Defaults()
	token := os.Getenv(c.TokenEnv)
	if token == "" {
		return nil, fmt.Errorf("prompt injection classifier token is missing in %s", c.TokenEnv)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.MaxIdleConnsPerHost = 4
	d := &Detector{cfg: c, token: token, transport: tr, client: &http.Client{Transport: tr, Timeout: time.Duration(c.TimeoutSeconds) * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if c.Provider == "jev" {
		return d, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(c.Endpoint, "/scan")+"/health", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := d.client.Do(req)
	if err != nil {
		d.Close()
		return nil, fmt.Errorf("prompt injection classifier unavailable")
	}
	defer res.Body.Close()
	var health struct {
		Model string `json:"model"`
		Ready bool   `json:"ready"`
	}
	if res.StatusCode != 200 || decode(res.Body, &health) != nil || !health.Ready || health.Model != c.Model {
		d.Close()
		return nil, fmt.Errorf("prompt injection classifier is not ready or model ID differs")
	}
	return d, nil
}
func (d *Detector) Close() {
	if d != nil {
		d.transport.CloseIdleConnections()
	}
}
func decode(reader io.Reader, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, 8193))
	if err != nil || len(data) > 8192 {
		return fmt.Errorf("invalid classifier response size")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing classifier response")
	}
	return nil
}
func (d *Detector) Scan(ctx context.Context, source string, payload []byte) Decision {
	if d == nil {
		return Decision{}
	}
	included := false
	for _, s := range d.cfg.Sources {
		if s == source {
			included = true
		}
	}
	if !included {
		return Decision{}
	}
	text, complete := prepareText(payload)
	sum := sha256.Sum256([]byte(text))
	result := Decision{Model: d.cfg.Model, Hash: hex.EncodeToString(sum[:])}
	fail := func(rule string) Decision { result.Block = true; result.Rule = rule; return result }
	if !complete {
		return fail("prompt_injection_payload_too_deep")
	}
	if len(text) > d.cfg.MaxInputBytes {
		return fail("prompt_injection_input_too_large")
	}
	if strings.TrimSpace(text) == "" {
		return result
	}
	if d.cfg.Provider == "jev" {
		return d.scanJev(ctx, source, text, result)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fail("prompt_injection_detector_error")
	}
	id := hex.EncodeToString(nonce)
	body, _ := json.Marshal(struct {
		ID     string `json:"id"`
		Source string `json:"source"`
		Text   string `json:"text"`
	}{id, source, text})
	req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fail("prompt_injection_detector_error")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.token)
	res, err := d.client.Do(req)
	if err != nil {
		return fail("prompt_injection_detector_unavailable")
	}
	defer res.Body.Close()
	var verdict struct {
		ID           string   `json:"id"`
		Model        string   `json:"model"`
		Score        *float64 `json:"injection_score"`
		Complete     bool     `json:"complete"`
		ScannedBytes int      `json:"scanned_bytes"`
		Windows      int      `json:"windows"`
	}
	if res.StatusCode != 200 || decode(res.Body, &verdict) != nil || verdict.ID != id || verdict.Model != d.cfg.Model || !verdict.Complete || verdict.ScannedBytes != len(text) || verdict.Windows < 1 || verdict.Score == nil || math.IsNaN(*verdict.Score) || math.IsInf(*verdict.Score, 0) || *verdict.Score < 0 || *verdict.Score > 1 {
		return fail("prompt_injection_invalid_verdict")
	}
	result.Score = *verdict.Score
	if result.Score >= d.cfg.Threshold {
		result.Rule = "prompt_injection"
		result.Block = d.cfg.Action == "block"
		result.Flag = d.cfg.Action == "flag"
	}
	return result
}

// Text keeps all decoded string values, including system/developer fields. The
// caller cannot evade scanning by changing a JSON role label. No silent truncation.
func Text(payload []byte) string { text, _ := prepareText(payload); return text }
func prepareText(payload []byte) (string, bool) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if dec.Decode(&value) != nil || dec.Decode(new(any)) != io.EOF {
		return string(payload), true
	}
	var out strings.Builder
	complete := true
	var walk func(any, int)
	walk = func(v any, depth int) {
		if depth > 256 {
			complete = false
			return
		}
		switch x := v.(type) {
		case string:
			trimmed := strings.TrimSpace(x)
			if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed)) {
				var inner any
				decoder := json.NewDecoder(strings.NewReader(trimmed))
				decoder.UseNumber()
				if decoder.Decode(&inner) == nil {
					walk(inner, depth+1)
					return
				}
			}
			out.WriteString(x)
			out.WriteByte('\n')
		case map[string]any:
			keys := make([]string, 0, len(x))
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				out.WriteString(key)
				out.WriteString(": ")
				walk(x[key], depth+1)
			}
		case []any:
			for _, v := range x {
				walk(v, depth+1)
			}
		default:
			fmt.Fprintln(&out, v)
		}
	}
	walk(value, 0)
	if !complete {
		return string(payload), false
	}
	return out.String(), true
}
