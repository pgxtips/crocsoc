# crocsoc (wip)

A complete RFC-compliant implementation of the websocket protocol.

## Development

** RFC-6455 1.3 Opening Handshake **

- [x] Accept, Track and Close imbound TCP conns
- [ ] Building a HTTP/1.1 (RFC2616) Opening Handshake RFC-6455 1.3

** To Address **
- [ ] conns may stay alive if FIN packet not sent on client termination

** Completed **

None

## Coverage

- [ ] tcp connections can be established, tracked and closed
- [ ] passes all server tests in the Autobahn Test Suite
