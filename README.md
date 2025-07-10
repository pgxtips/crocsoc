# Crocodile Websocket (wip)

A complete RFC-compliant implementation of the websocket protocol.

## Development

- [x] RFC-6455 1.3 Opening Handshake (basic)
- [x] RFC-6455 4.2.1 Reading the Client's Opening Handshake (full spec)
- [x] RFC-6455 4.2.2 Sending the Server's Opening Handshake
- [x] Hijack the TCP connection after Handshake
- [x] RFC-6455 5.2 Frame Read (single frame)
- [x] RFC-6455 5.3 Client-to-Server Masking
- [x] RFC-6455 5.4 Fragmentation (fragmented frames)
- [x] RFC-6455 5.5.1 Close
- [x] RFC-6455 5.5.2 Ping (processing client ping)
- [x] RFC-6455 5.5.3 Pong
- [x] RFC-6455 5.6 Data Frames (Text & Binary)


** To Address **

- [ ] does not implement the use of any subprotocols e.g. chat, superchat, etc.
- [ ] currently does not fragment outgoing messages.

## Running tests

for standard go test output

```

go test ./crocsoc -v

```

for prettier go test output

```

go test ./crocsoc -v -json | tparse -all

```

## Coverage
- [ ] passes all server tests in the Autobahn Test Suite
