package crocsoc

import (
	"bytes"
	"net"
	"sync"
	"testing"
)

/*
ALL TESTING VALUES PROVIDED FROM EXAMPLES IN RFC-6455

[x] A single-frame unmasked text message
-> 0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains "Hello")

[x] A single-frame masked text message
-> 0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58 (contains "Hello")

[x] A fragmented unmasked text message
-> 0x01 0x03 0x48 0x65 0x6c (contains "Hel")
-> 0x80 0x02 0x6c 0x6f (contains "lo")

Unmasked Ping request and masked Ping response
-> 0x89 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains a body of "Hello", but the contents
of the body are arbitrary)
-> 0x8a 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58 (contains a body
of "Hello", matching the body of the ping)

256 bytes binary message in a single unmasked frame
-> 0x82 0x7E 0x0100 [256 bytes of binary data]

64KiB binary message in a single unmasked frame
-> 0x82 0x7F 0x0000000000010000 [65536 bytes of binary data]

*/

func TestUnmaskedFrame(t *testing.T){
	d := []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func(){
		_, err := clientConn.Write(d)
		if err != nil {
			t.Errorf("failed to write test data: %v", err)
		}
	}()

	msg, err := ReadMessage(serverConn)

	if err != nil {
		t.Errorf("%v", err)
	}

	want := "Hello"
	if want != string(msg) {
		t.Errorf("want: %v, got: %v", want, string(msg))
	}
}

func TestMaskedFrame(t *testing.T){
	d := []byte{0x81,0x85,0x37,0xfa,0x21,0x3d,0x7f,0x9f,0x4d,0x51,0x58}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func(){
		_, err := clientConn.Write(d)
		if err != nil {
			t.Errorf("failed to write test data: %v", err)
		}
	}()

	msg, err := ReadMessage(serverConn)

	if err != nil {
		t.Errorf("%v", err)
	}

	want := "Hello"
	if want != string(msg) {
		t.Errorf("want: %v, got: %v", want, string(msg))
	}
}

func TestFragmentedFrames(t *testing.T){
	d := []byte{
		0x01, 0x03, 0x48, 0x65, 0x6c,
		0x80, 0x02, 0x6c, 0x6f,
	}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func(){
		_, err := clientConn.Write(d)
		if err != nil {
			t.Errorf("failed to write test data: %v", err)
		}
	}()

	msg, err := ReadMessage(serverConn)
	if err != nil {
		t.Errorf("%v", err)
	}

	want := "Hello"
	if want != string(msg) {
		t.Errorf("want: %v, got: %v", want, msg)
	}
}

func TestPingPongFrames(t *testing.T) {
	ping := []byte{
		0x89, 0x05, 'H', 'e', 'l', 'l', 'o',
	}

	serverConn, clientConn := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(3)

	// Client writes ping
	go func(){
		defer wg.Done()
		_, err := clientConn.Write(ping)
		if err != nil {
			t.Errorf("client write error: %v", err)
		}
	}()

	// Server responds pong (this will never end as there is no fin bit) 
	go func(){
		defer wg.Done()
		_, err := ReadMessage(serverConn)
		if err != nil {
			t.Errorf("ReadMessage error: %v", err)
		}
	}()

	// Client reads pong
	go func(){
		defer wg.Done()

		// Read pong header
		header := make([]byte, 2)
		_, err := clientConn.Read(header)
		if err != nil {
			t.Errorf("client read error: %v", err)
			return
		}

		opcode := header[0] & 0x0F
		payloadLen := int(header[1] & 0x7F)

		payload := make([]byte, payloadLen)
		_, err = clientConn.Read(payload)
		if err != nil {
			t.Errorf("client payload read error: %v", err)
			return
		}

		// pong opcode
		if opcode != 0x0a {
			t.Errorf("want: 0x0a, got: %x", opcode)
		}

		if string(payload) != "Hello" {
			t.Errorf("want: Hello, got: %s", string(payload))
		}

		// t.Logf("Opcode: %02x", opcode)
		// t.Logf("Payload: %s", payload)
		clientConn.Close()
	}()

	wg.Wait()
}

func TestBinary256Frame(t *testing.T) {
	// create 256-byte payload
	payload := bytes.Repeat([]byte{0xFF}, 256)

	// frame header:
	// - 0x82 = FIN + binary frame
	// - 0x7E signals 16-bit extended payload length follows
	// - 0x01 0x00 = length 256 bytes
	frame := []byte{
		0x82,
		0x7E,
		0x01, 0x00,
	}
	frame = append(frame, payload...)

	serverConn, clientConn := net.Pipe()

	// write frame to the "client" side
	go func() {
		clientConn.Write(frame)
	}()

	msg, err := ReadMessage(serverConn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(msg, payload) {
		t.Errorf("payload mismatch: got %x, want %x", msg, payload)
	}
}

func TestBinary64kFrame(t *testing.T) {
	// create 256-byte payload
	payload := bytes.Repeat([]byte{0xFF}, 65536)

	// frame header:
	// - 0x82 = FIN + binary frame
	// - 0x7E signals 16-bit extended payload length follows
	// - 0x01 0x00 = length 256 bytes
	frame := []byte{
		0x82,
		0x7F,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00,
	}
	frame = append(frame, payload...)

	serverConn, clientConn := net.Pipe()

	// write frame to the "client" side
	go func() {
		clientConn.Write(frame)
	}()

	msg, err := ReadMessage(serverConn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(msg, payload) {
		t.Errorf("payload mismatch: got %x, want %x", msg, payload)
	}
}


