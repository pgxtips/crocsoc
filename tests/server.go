package tests

import (
	"net/http"
	"github.com/pgxtips/crocsoc"
)

func StartServer(){
	http.HandleFunc("/ws", crocsoc.WsHandler)
	_ = http.ListenAndServe(":8080", nil)
}
