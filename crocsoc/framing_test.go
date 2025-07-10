package crocsoc

import (
	"bytes"
	"testing"
)

/*
ALL TESTING VALUES PROVIDED FROM EXAMPLES IN RFC-6455

A single-frame unmasked text message
	-> 0x81 0x05 0x48 0x65 0x6c 0x6c 0x6f (contains "Hello")

A single-frame masked text message
	-> 0x81 0x85 0x37 0xfa 0x21 0x3d 0x7f 0x9f 0x4d 0x51 0x58 (contains "Hello")

A fragmented unmasked text message
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
	r := bytes.NewReader(d)

	msg, err := ReadMessage(r)

	if err != nil {
		t.Errorf("%v", err)
	}

	want := "Hello"
	if want != msg {
		t.Errorf("want: %v, got: %v", want, msg)
	}
}

func TestMaskedFrame(t *testing.T){
	d := []byte{0x81,0x85,0x37,0xfa,0x21,0x3d,0x7f,0x9f,0x4d,0x51,0x58}
	r := bytes.NewReader(d)

	msg, err := ReadMessage(r)

	if err != nil {
		t.Errorf("%v", err)
	}

	want := "Hello"
	if want != msg {
		t.Errorf("want: %v, got: %v", want, msg)
	}
}

func TestFragmentedFrames(t *testing.T){
	d := []byte{
		0x01, 0x03, 0x48, 0x65, 0x6c,
		0x80, 0x02, 0x6c, 0x6f,
	}
	r := bytes.NewReader(d)

	msg, err := ReadMessage(r)

	if err != nil {
		t.Errorf("%v", err)
	}

	want := "Hello"
	if want != msg {
		t.Errorf("want: %v, got: %v", want, msg)
	}
}

