package crocsoc

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

/*
ALL TESTING VALUES PROVIDED FROM EXAMPLES IN RFC-6455
*/

/*
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: http://example.com
Sec-WebSocket-Protocol: chat, superchat
Sec-WebSocket-Version: 13
*/


func buildRequest(headers map[string]string) *http.Request {
	r, _ := http.NewRequest("GET", "/chat", nil)
	r.Host = "localhost:8080"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestHeadersHappy(t *testing.T){
	r := buildRequest(map[string]string{
		"Upgrade": "websocket",
		"Connection": "Upgrade",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
	})

	err := ValidateHeaders(r)
	if err != nil {
		t.Errorf("%v", err)
	}

	// origin header is optional
	r = buildRequest(map[string]string{
		"Upgrade": "websocket",
		"Connection": "Upgrade",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
		"Origin": "http://example.com",
	})
	err = ValidateHeaders(r)
	if err != nil {
		t.Errorf("%v", err)
	}

	// protocol header is optional
	r = buildRequest(map[string]string{
		"Upgrade": "websocket",
		"Connection": "Upgrade",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
		"Origin": "http://example.com",
		"Sec-WebSocket-Protocol": "chat, superchat",
	})
	err = ValidateHeaders(r)
	if err != nil {
		t.Errorf("%v", err)
	}
}


/*
In further revisions, add permutations of all missing headers.
2^4 = 16
*/
func TestHeadersUnhappy(t *testing.T){
	r := buildRequest(map[string]string{
		"Connection": "Upgrade",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
	})

	err := ValidateHeaders(r)
	if err == nil {
		t.Errorf("unhappy request headers accepted")
	}

	r = buildRequest(map[string]string{
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
	})

	err = ValidateHeaders(r)
	if err == nil {
		t.Errorf("unhappy request headers accepted")
	}

	r = buildRequest(map[string]string{
		"Sec-WebSocket-Version": "13",
	})

	err = ValidateHeaders(r)
	if err == nil {
		t.Errorf("unhappy request headers accepted")
	}

	r = buildRequest(map[string]string{ })
	err = ValidateHeaders(r)
	if err == nil {
		t.Errorf("unhappy request headers accepted")
	}
}

func TestSha1(t *testing.T){
	wk := "dGhlIHNhbXBsZSBub25jZQ=="
	val := SecAcceptSha(wk)
	expected := []byte{0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38, 0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea}

	if !bytes.Equal(val, expected){
		t.Fatalf("unexpected value: %x . should be: %x", val, expected)
	}
}

func TestB64(t *testing.T){
	h := []byte{0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38, 0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea}
	b64 := base64.StdEncoding.EncodeToString(h)
	expected := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	if b64 != expected {
		t.Fatalf("unexpected value: %s . should be: %s", b64, expected)
	}
}

func TestOpeningHandshake(t * testing.T){
	r := buildRequest(map[string]string{
		"Upgrade": "websocket",
		"Connection": "Upgrade",
		"Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
		"Origin": "http://example.com",
		"Sec-WebSocket-Protocol": "chat, superchat",
	})

	w := httptest.NewRecorder()

	OpeningHandshake(w, r)

	resp := w.Result()
	defer resp.Body.Close()

	// check status
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}

	// check headers
	if got := resp.Header.Get("Upgrade"); got != "websocket" {
		t.Errorf("missing or wrong Upgrade header: %q", got)
	}
	if got := resp.Header.Get("Connection"); got != "Upgrade" {
		t.Errorf("missing or wrong Connection header: %q", got)
	}

	// check accept b64
	accept := resp.Header.Get("Sec-WebSocket-Accept")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if accept != want {
		t.Errorf("unexpected Sec-WebSocket-Accept: got %q, want %q", accept, want)
	}

	// check subprotocols
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != "" {
		t.Logf("Sec-WebSocket-Protocol negotiated: %s", got)
	}
}
