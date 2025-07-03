package tests

import (
	"fmt"
	"net/http"
	"github.com/pgxtips/crocsoc"
)

func StartServer(port string){
	http.HandleFunc("/ws", crocsoc.WsHandler)
	portStr := fmt.Sprintf(":%s", port)
	_ = http.ListenAndServe(portStr, nil)
} 
