package crocsoc

import (
	"log/slog"
	"net/http"
)

func WsHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("handling socket connection")
}
