package tests

import (
	"testing"
	"time"
	"net/http"
)

func TestHttpEp(t *testing.T){
	go StartServer()
	time.Sleep(150 * time.Millisecond)

	resp, err := http.Get("http://localhost:8080/ws")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}	
}

func TestHttpHandshake(t *testing.T){
	go StartServer()
	time.Sleep(150 * time.Millisecond)
}
