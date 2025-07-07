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

When a client establishes a WebSocket connection to a server, the
server MUST complete the following steps to accept the connection and
send the server's opening handshake.

1. If the connection is happening on an HTTPS (HTTP-over-TLS) port,
   perform a TLS handshake over the connection.  If this fails
   (e.g., the client indicated a host name in the extended client
   hello "server_name" extension that the server does not host),
   then close the connection; otherwise, all further communication
   for the connection (including the server's handshake) MUST run
   through the encrypted tunnel [RFC5246].

** The above should be handled by the developers using this library. go's net/http
server should be served on 8443 and serve the key and cert needed for tls **

2. The server can perform additional client authentication, for
   example, by returning a 401 status code with the corresponding
   |WWW-Authenticate| header field as described in [RFC2616].

3. The server MAY redirect the client using a 3xx status code
   [RFC2616].  Note that this step can happen together with, before,
   or after the optional authentication step described above.

** The above should be handled by the developers using this library. Authentication
requirements should be handled before reaching the ws endpoint and handle rejections 
and acceptions accordingly**

4.  Establish the following information:

   /origin/
	  The |Origin| header field in the client's handshake indicates
	  the origin of the script establishing the connection.  The
	  origin is serialized to ASCII and converted to lowercase.  The
	  server MAY use this information as part of a determination of
	  whether to accept the incoming connection.  If the server does
	  not validate the origin, it will accept connections from
	  anywhere.  If the server does not wish to accept this
	  connection, it MUST return an appropriate HTTP error code
	  (e.g., 403 Forbidden) and abort the WebSocket handshake
	  described in this section.  For more detail, refer to
	  Section 10.

   /key/
	  The |Sec-WebSocket-Key| header field in the client's handshake
	  includes a base64-encoded value that, if decoded, is 16 bytes
	  in length.  This (encoded) value is used in the creation of
	  the server's handshake to indicate an acceptance of the
	  connection.  It is not necessary for the server to base64-
	  decode the |Sec-WebSocket-Key| value.

   /version/
	  The |Sec-WebSocket-Version| header field in the client's
	  handshake includes the version of the WebSocket Protocol with
	  which the client is attempting to communicate.  If this
	  version does not match a version understood by the server, the
	  server MUST abort the WebSocket handshake described in this
	  section and instead send an appropriate HTTP error code (such
	  as 426 Upgrade Required) and a |Sec-WebSocket-Version| header
	  field indicating the version(s) the server is capable of
	  understanding.

   /resource name/
	  An identifier for the service provided by the server.  If the
	  server provides multiple services, then the value should be
	  derived from the resource name given in the client's handshake
	  in the "Request-URI" [RFC2616] of the GET method.  If the
	  requested service is not available, the server MUST send an
	  appropriate HTTP error code (such as 404 Not Found) and abort
	  the WebSocket handshake.

   /subprotocol/
	  Either a single value representing the subprotocol the server
	  is ready to use or null.  The value chosen MUST be derived
	  from the client's handshake, specifically by selecting one of
	  the values from the |Sec-WebSocket-Protocol| field that the
	  server is willing to use for this connection (if any).  If the
	  client's handshake did not contain such a header field or if
	  the server does not agree to any of the client's requested
	  subprotocols, the only acceptable value is null.  The absence
	  of such a field is equivalent to the null value (meaning that
	  if the server does not wish to agree to one of the suggested
	  subprotocols, it MUST NOT send back a |Sec-WebSocket-Protocol|
	  header field in its response).  The empty string is not the
	  same as the null value for these purposes and is not a legal
	  value for this field.  The ABNF for the value of this header
	  field is (token), where the definitions of constructs and
	  rules are as given in [RFC2616].

   /extensions/
	  A (possibly empty) list representing the protocol-level
	  extensions the server is ready to use.  If the server supports
	  multiple extensions, then the value MUST be derived from the
	  client's handshake, specifically by selecting one or more of
	  the values from the |Sec-WebSocket-Extensions| field.  The
	  absence of such a field is equivalent to the null value.  The
	  empty string is not the same as the null value for these
	  purposes.  Extensions not listed by the client MUST NOT be
	  listed.  The method by which these values should be selected
	  and interpreted is discussed in Section 9.1.

5.  If the server chooses to accept the incoming connection, it MUST
   reply with a valid HTTP response indicating the following.

   1.  A Status-Line with a 101 response code as per RFC 2616
	   [RFC2616].  Such a response could look like "HTTP/1.1 101
	   Switching Protocols".

   2.  An |Upgrade| header field with value "websocket" as per RFC
	   2616 [RFC2616].

   3.  A |Connection| header field with value "Upgrade".

   4.  A |Sec-WebSocket-Accept| header field.  The value of this
	   header field is constructed by concatenating /key/, defined
	   above in step 4 in Section 4.2.2, with the string "258EAFA5-
	   E914-47DA-95CA-C5AB0DC85B11", taking the SHA-1 hash of this
	   concatenated value to obtain a 20-byte value and base64-
	   encoding (see Section 4 of [RFC4648]) this 20-byte hash.

	   The ABNF [RFC2616] of this header field is defined as
	   follows:

	   Sec-WebSocket-Accept     = base64-value-non-empty
	   base64-value-non-empty = (1*base64-data [ base64-padding ]) |
								base64-padding
	   base64-data      = 4base64-character
	   base64-padding   = (2base64-character "==") |
						  (3base64-character "=")
	   base64-character = ALPHA | DIGIT | "+" | "/"

NOTE: As an example, if the value of the |Sec-WebSocket-Key| header
field in the client's handshake were "dGhlIHNhbXBsZSBub25jZQ==", the
server would append the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
to form the string "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-
C5AB0DC85B11".  The server would then take the SHA-1 hash of this
string, giving the value 0xb3 0x7a 0x4f 0x2c 0xc0 0x62 0x4f 0x16 0x90
0xf6 0x46 0x06 0xcf 0x38 0x59 0x45 0xb2 0xbe 0xc4 0xea.  This value
is then base64-encoded, to give the value
"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", which would be returned in the
|Sec-WebSocket-Accept| header field.

5.  Optionally, a |Sec-WebSocket-Protocol| header field, with a
   value /subprotocol/ as defined in step 4 in Section 4.2.2.

6.  Optionally, a |Sec-WebSocket-Extensions| header field, with a
   value /extensions/ as defined in step 4 in Section 4.2.2.  If
   multiple extensions are to be used, they can all be listed in
   a single |Sec-WebSocket-Extensions| header field or split
   between multiple instances of the |Sec-WebSocket-Extensions|
   header field.

This completes the server's handshake.  If the server finishes these
steps without aborting the WebSocket handshake, the server considers
the WebSocket connection to be established and that the WebSocket
connection is in the OPEN state.  At this point, the server may begin
sending (and receiving) data.

*/

func OpeningHandshake(w http.ResponseWriter, r *http.Request) error {

	// only allow GET methods
	if r.Method != http.MethodGet {
		return fmt.Errorf("Method Not Allowed")
	}

	// ensure that headers are correctly received 
	if err := ValidateHeaders(r); err != nil {
		return fmt.Errorf(err.Error())
	}

	// create the server response hash
	h := SecAcceptSha(r.Header.Get("Sec-WebSocket-Key"))
	b64 := base64.StdEncoding.EncodeToString(h)

	w.Header().Add("Upgrade", "websocket")
	w.Header().Add("Connection", "Upgrade")
	w.Header().Add("Sec-WebSocket-Accept", b64)
	w.WriteHeader(http.StatusSwitchingProtocols)

	return nil
}
