# TCP Handshake Simple Implementation

**Disclaimer - This implementation is for educational purposes only.**

This is an implementation of the server-client handshake process as defined in TLS 1.3 and a simple ping-pong requests
encrypted communication between them. The server works asynchronously, the implementation is not optimized at all but it
can handle about a 100 concurrent client connections.

It implements only parts of RFC 8446, RFC 5958, RFC 5869, RFC 5246, RFC 4492 and others.
A very important step is omitted in the handshake process, namely certificate validation, without which
man-in-the-middle attacks are easy to pull off.

For information on make targets run:
```bash
make help
```

Credit to TLS Header fields illustrated for the excellent visual representation: https://tls.ulfheim.net/