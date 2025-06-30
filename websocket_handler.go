package crocsoc 

import (
	"net/http"
	"log/slog"
)

func WsHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("handling socket connection")
}
