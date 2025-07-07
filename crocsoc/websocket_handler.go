package crocsoc

import (
	"fmt"
	"log/slog"
	"net/http"
)

func WsHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("ws handler")

	// handle OpeningHandshake
	if err := OpeningHandshake(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return 
	}
	
	// hijack tcp 
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, rw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Hijacking failed: %v", err), http.StatusInternalServerError)
		return 
	}

	// build connection object
	wsConn := WSConn{
		Conn: conn,
		RW: rw, 
		Subprotocol: r.Header.Get("Sec-WebSocket-Protocol"),
		IsClosed: false,
	}

	// offloads handling of connection to go routine for communicating frame data
	go ServeConn(wsConn)
}
