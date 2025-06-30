package main

import (
	"os"
	"log/slog"
	"github.com/pgxtips/crocsoc/server"
)

func main(){
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	server.StartServer("0.0.0.0", "8080")
} 
