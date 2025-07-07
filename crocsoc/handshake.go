package crocsoc

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
)

/*
WebSocket client's handshake is an HTTP Upgrade request:

================================================
	GET /chat HTTP/1.1
	Host: server.example.com
	Upgrade: websocket
	Connection: Upgrade
	Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	Origin: http://example.com
	Sec-WebSocket-Protocol: chat, superchat
	Sec-WebSocket-Version: 13
================================================

- validate the all the websocket specific headers a present (Upgrade, Connection,
Sec-WebSocket-Key, Sec-WebSocket-Version)

- server selects ONE of the acceptable protocols and echoes the value in the
handshake (e.g. Sec-WebSocket-Protocol: chat)

The server is informed of the script origin generating the WebSocket
connection request.  If the server does not wish to accept connections
from this origin, it can choose to reject the connection by sending an
appropriate HTTP error code.  This header field is sent by browser clients;
for non-browser clients, this header field may be sent if it makes sense in
the context of those clients.
	- As the origin header is not required it should be handled by developers,
	can be controlled using origin access control provided by http servers.

Only accept websocket connections to prevent attacks. E.g. sending a
websocket server packets that are carefully crafted using XMLHttpRequest or a
form submission.
*/

/*
The client's opening handshake consists of the following parts.  If
the server, while reading the handshake, finds that the client did
not send a handshake that matches the description below (note that as
per [RFC2616], the order of the header fields is not important),
including but not limited to any violations of the ABNF grammar
specified for the components of the handshake, the server MUST stop
processing the client's handshake and return an HTTP response with an
appropriate error code (such as 400 Bad Request).

[x] - An HTTP/1.1 or higher GET request, including a "Request-URI"
	[RFC2616] that should be interpreted as a /resource name/
	defined in Section 3 (or an absolute HTTP/HTTPS URI containing
	the /resource name/).

[x] - A |Host| header field containing the server's authority.

[x] - An |Upgrade| header field containing the value "websocket",
	treated as an ASCII case-insensitive value.

[x] - A |Connection| header field that includes the token "Upgrade",
	treated as an ASCII case-insensitive value.

[x] - A |Sec-WebSocket-Key| header field with a base64-encoded (see
	Section 4 of [RFC4648]) value that, when decoded, is 16 bytes in
	length.

[x] - A |Sec-WebSocket-Version| header field, with a value of 13.

[ ] - Optionally, an |Origin| header field.  This header field is sent
	by all browser clients.  A connection attempt lacking this
	header field SHOULD NOT be interpreted as coming from a browser
	client.

[ ] - Optionally, a |Sec-WebSocket-Protocol| header field, with a list
	of values indicating which protocols the client would like to
	speak, ordered by preference.

[ ] - Optionally, a |Sec-WebSocket-Extensions| header field, with a
	list of values indicating which extensions the client would like
	to speak.  The interpretation of this header field is discussed
	in Section 9.1.

Optionally, other header fields, such as those used to send
	cookies or request authentication to a server.  Unknown header
	fields are ignored, as per [RFC2616].
*/

// Ensures that all the required headers and values for the 
// "1.3 Opening Handshake" are present in GET request.
func ValidateHeaders(r *http.Request) error {
	// header validation
    wh := r.Host
    wv := r.Header.Get("Sec-WebSocket-Version")
    wk := r.Header.Get("Sec-WebSocket-Key")
    wu := r.Header.Get("Upgrade")
    wc := r.Header.Get("Connection")

	// check host
	if wh == "" {
		return fmt.Errorf("missing host header")
	}

	// check exists
	if slices.Contains([]string{wv, wk, wu, wc}, "") {
		return fmt.Errorf("missing required headers")
	}

	// check upgrade header is websocket
	if strings.ToLower(wu) != "websocket" {
		return fmt.Errorf("invalid upgrade value")
	}

	// check connection header contains upgrade value
	connVals := strings.Split(wc, ",")

	for i := range connVals {
		connVals[i] = strings.ToLower(connVals[i])
	}

	if !slices.Contains(connVals, "upgrade"){
		return fmt.Errorf("connection missing upgrade value")
	}

	// ensure that the Sec-WebSocket-Version is 13 as per the RFC
	if wv != "13" {
		return fmt.Errorf("Invalid Sec-WebSocket-Version")
	}

	// check that the client key decoded to 16 bytes
	decodedKey, err := base64.StdEncoding.DecodeString(wk)
	if err != nil {
		return fmt.Errorf("failed to decode client key: %v", err)
	}
	if len(decodedKey) != 16 {
		return fmt.Errorf("Sec-WebSocket-Key exceeds 16 bytes, got: %v", decodedKey)
	}

	return nil
}

/*
To prove that the handshake was received, the server has to take two
pieces of information and combine them to form a response.  The first
piece of information comes from the |Sec-WebSocket-Key| header field
in the client handshake:

	Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

Concretely, if as in the example above, the |Sec-WebSocket-Key|
header field had the value "dGhlIHNhbXBsZSBub25jZQ==", the server
would concatenate the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
to form the string "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-
C5AB0DC85B11".  The server would then take the SHA-1 hash of this,
giving the value 0xb3 0x7a 0x4f 0x2c 0xc0 0x62 0x4f 0x16 0x90 0xf6
0x46 0x06 0xcf 0x38 0x59 0x45 0xb2 0xbe 0xc4 0xea.  This value is
then base64-encoded (see Section 4 of [RFC4648]), to give the value
"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".  This value would then be echoed in
the |Sec-WebSocket-Accept| header field.
*/


// SHA-1 hashes Sec-WebSocket-Key as part of the "1.3 Opening Handshake". 
// This hash value must be base64 encoded before writing the 
// Sec-WebSocket-Accept header!

func SecAcceptSha(wk string) []byte {
	const guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wk = strings.TrimSpace(wk)

	hash := sha1.New()
	io.WriteString(hash, wk)
	io.WriteString(hash, guid)

	return hash.Sum(nil)
}

/*
Successful connection (server response):

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

These fields are checked by the WebSocket client for scripted pages.
If the |Sec-WebSocket-Accept| value does not match the expected
value, if the header field is missing, or if the HTTP status code is
not 101, the connection will not be established, and WebSocket frames
will not be sent.

Option fields can also be included.  In this version of the protocol,
the main option field is |Sec-WebSocket-Protocol|, which indicates
the subprotocol that the server has selected.  WebSocket clients
verify that the server included one of the values that was specified
in the WebSocket client's handshake.  A server that speaks multiple
subprotocols has to make sure it selects one based on the client's
handshake and specifies it in its handshake. e.g.

Sec-WebSocket-Protocol: chat

The server can also set cookie-related option fields to _set_
cookies, as described in [RFC6265].
*/

func OpeningHandshake(w http.ResponseWriter, r *http.Request) {

	// only allow GET methods
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusBadRequest)
	}

	// ensure that headers are correctly sent
	if err := ValidateHeaders(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// create the server response hash
	h := SecAcceptSha(r.Header.Get("Sec-WebSocket-Key"))
	b64 := base64.StdEncoding.EncodeToString(h)


	w.Header().Add("Upgrade", "websocket")
	w.Header().Add("Connection", "Upgrade")
	w.Header().Add("Sec-WebSocket-Accept", b64)
	w.WriteHeader(http.StatusSwitchingProtocols)
}
