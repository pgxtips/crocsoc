package crocsoc

import (
	"net"
	"bufio"
)

type WSConn struct {
	Conn net.Conn
	RW   *bufio.ReadWriter
	Subprotocol string
	IsClosed    bool
}

func ServeConn(conn WSConn) {
	for {
	}
}
