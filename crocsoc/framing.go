package crocsoc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"unicode/utf8"
)

type Frame struct{
	Fin bool
	Opcode byte 
	Payload []byte
}

func ReadMessage(conn net.Conn) (string, error) {
	frags := []*Frame{}
	var initialOpcode byte

	for {
		frame, err := readFrame(conn)

		if err != nil {
			// connection closed normally
			if errors.Is(err, io.EOF) {
				return "", nil
			}
			return "", fmt.Errorf("error reading message: %v", err)
		}

		// handle control frames
		if isControlFrame(frame){
			handleControlFrame(frame, conn)
			continue
		}

		// first new frame of new batch
		if len(frags) == 0 {
			initialOpcode = frame.Opcode
			// only text and binary frames accepted
			if initialOpcode != 0x1 && initialOpcode != 0x2 {
				return "", fmt.Errorf("unsupported opcode %x", initialOpcode)
			}
		} else {
			// all subsequent fragments must be continuation frames opcode 0x0
			if frame.Opcode != 0x0 {
				return "", fmt.Errorf("unexpected opcode %x in continuation frame", frame.Opcode)
			}
		}

		frags = append(frags, frame)

		// combine payloads
		if frame.Fin {
			var payload []byte 
			for _, f := range frags {
				payload = append(payload, f.Payload...)
			}

			// text frame
			if initialOpcode == 0x1 {
				if !utf8.Valid(payload) {
					return "", fmt.Errorf("invalid UTF-8 in text frame")
				}
				return string(payload), nil
			}

			// @todo: binary frame (for now just error)
			if initialOpcode == 0x2 {
				return "", fmt.Errorf("binary frames not supported yet")
			}

			return "", fmt.Errorf("unknown opcode: %x", frame.Opcode)
		}
	}
}

func isControlFrame(f *Frame) bool{
	switch f.Opcode{
		case 0x8, // close
		0x9,   // ping
		0xA:   // pong
		return true
	default:
		return false
	}
}

func handleControlFrame(f *Frame, conn io.Writer) error{
	switch f.Opcode {
	//close
	case 0x8:
		var code uint16
		var reason string

		if len(f.Payload) >= 2 {
			code = binary.BigEndian.Uint16(f.Payload[:2])
			reason = string(f.Payload[2:])
		}

		fmt.Printf("Received close frame: code=%d, reason=%q\n", code, reason)
		return SendCloseFrame(conn, 1000, "Closing in response")
	// ping 
	case 0x9:
		fmt.Println("Received ping")
		return SendPongFrame(conn, f.Payload)
	// pong 
	case 0xA:
		fmt.Println("Received pong")
		return nil
	default:
		return fmt.Errorf("unknown control frame opcode: %x", f.Opcode)
	}
}

func readFrame(conn net.Conn) (*Frame, error) {
	header := [2]byte{};
	_, err := io.ReadFull(conn, header[:])

	if err != nil {
		// connection closed normally
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}

		return nil, fmt.Errorf("failed to read frame header: %v", err)
	}

	// first byte of header:
	// fin (1 bit), rsv1 (1 bit), rsv2 (1 bit), rsv3 (1 bit), opcode (4 bit)
	b0 := header[0]
	fin := b0 & 0x80 != 0
	opcode := b0 & 0x0F

	// second byte of header:
	b1 := header[1]
	mask := b1 & 0x80 != 0
	payLen := int(b1 & 0x7F)

/*
-> If payload length 0-125, that is the payload length.  
-> If 126, the following 2 bytes interpreted as a 16-bit unsigned integer 
are the payload length.  
-> If 127, the following 8 bytes interpreted as a 64-bit unsigned integer (the
most significant bit MUST be 0) are the payload length.  

Multibyte length quantities are expressed in network byte order.  
Note that in all cases, the minimal number of bytes MUST be used to encode
the length, for example, the length of a 124-byte-long string
CAN'T be encoded as the sequence 126, 0, 124.  

The payload length is the length of the "Extension data" + the length of the
"Application data".  The length of the "Extension data" may be
zero, in which case the payload length is the length of the "Application data".
*/
	if payLen == 126 {
		var ext [2]byte
		io.ReadFull(conn, ext[:])
		payLen = int(binary.BigEndian.Uint16(ext[:]))
	} else if payLen == 127 {
		var ext [8]byte
		io.ReadFull(conn, ext[:])
		payLen64 := binary.BigEndian.Uint64(ext[:])
		payLen = int(payLen64)
	}

	maskingKey := [4]byte{};
	if mask {
		io.ReadFull(conn, maskingKey[:])
	}

	payload := make([]byte, payLen)
	io.ReadFull(conn, payload)

	if mask {
		for i := range payLen {
			/*
				Masking key (4 byte mask): [A B C D]
				Payload: [p0 ^ A, p1 ^ B, p2 ^ C, p3 ^ D, p4 ^ A,  p5 ^ B...]
			*/
			payload[i] ^= maskingKey[i%4]
		}
	}

	return &Frame{
		Fin: fin,
		Opcode: opcode,
		Payload: payload,
	}, nil
}

func SendTextFrame(w io.Writer, data []byte) error {
	frame := &Frame{
		Fin:     true,
		Opcode:  0x1, // text frame
		Payload: data,
	}
	return WriteFrame(w, frame)
}

func SendPongFrame(w io.Writer, payload []byte) error {
	frame := &Frame{
		Fin:     true,
		Opcode:  0xA, // pong frame
		Payload: payload,
	}
	return WriteFrame(w, frame)
}

func SendCloseFrame(w io.Writer, code uint16, reason string) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], reason)

	frame := &Frame{
		Fin:     true,
		Opcode:  0x8, // close frame
		Payload: payload,
	}
	return WriteFrame(w, frame)
}

func SendBinaryFrame(w io.Writer, data []byte) error {
	frame := &Frame{
		Fin:     true,
		Opcode:  0x2, // binary frame
		Payload: data,
	}
	return WriteFrame(w, frame)
}

func WriteFrame(w io.Writer, f *Frame) error {
	// header[0] byte
	var b0 byte

	if f.Fin {
		b0 |= 0x80
	}

	b0 |= f.Opcode & 0x0F

	header := []byte{b0}

	// header[1] byte
	// no mask bit needed (server -> client)
	var b1 byte = 0x0

	payloadLen := len(f.Payload)

	switch {
	case payloadLen <= 125:
		b1 |= byte(payloadLen)
		header = append(header, b1)
	// uint16
	case payloadLen <= 65535:
		b1 |= 126
		header = append(header, b1)

		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(payloadLen))
		header = append(header, ext...)

	default:
		b1 |= 127
		header = append(header, b1)

		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(payloadLen))
		header = append(header, ext...)
	}

	// send header first seperately to allow larger payloads
	_, err := w.Write(header)
	if err != nil {
		return err
	}

	_, err = w.Write(f.Payload)
	return err
}
