package tests

import (
	"testing"
	"time"
	"net/http"
)

// testing the endpoint exists and functions
func TestHttpEp(t *testing.T){
	go StartServer("8080")
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

// func TestHttpHandshake(t *testing.T){
// 	go StartServer("8080")
// 	time.Sleep(150 * time.Millisecond)
// }
