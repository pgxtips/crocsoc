package crocsoc

import (
	"fmt"
	"log/slog"
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
Sec-WebSocket-Key, Sec-WebSocket-Protocol, Sec-WebSocket-Version)

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

Summary Checklist:

[x] - client to include Sec-WebSocket-Version header in request
[x] - client to include Sec-WebSocket-Key header in request
[x] - client to include Upgrade header in request
[x] - client to include Connection header in request

*/

func validateHeaders(r *http.Request) error {
	// header validation
    wv := r.Header.Get("Sec-WebSocket-Version")
    wk := r.Header.Get("Sec-WebSocket-Key")
    wu := r.Header.Get("Upgrade")
    wc := r.Header.Get("Connection")

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

	return nil
}

func openingHandshake(w http.ResponseWriter, r *http.Request) {
	if err := validateHeaders(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

}

func WsHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("handling socket connection")
}
