# Crocodile Websocket (wip)

A complete RFC-compliant implementation of the websocket protocol.

## Development

- [x] RFC-6455 1.3 Opening Handshake (basic)
- [ ] RFC-6455 4.2.1 Reading the Client's Opening Handshake (full spec)


** To Address **

- [ ] The lib does not implement the use of any subprotocols e.g. chat, superchat, etc.

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
