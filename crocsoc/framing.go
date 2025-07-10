package crocsoc

import (
	"encoding/binary"
	"fmt"
	"io"
)

type Frame struct{
	Fin bool
	Opcode byte 
	Payload []byte
}

func ReadFrame(conn io.Reader) (*Frame, error) {
	header := [2]byte{};
	_, err := io.ReadFull(conn, header[:])

	if err != nil {
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
