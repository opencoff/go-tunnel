# UDP processing notes

To support UDP seamlessly, we need to rearchitect the server code.

- socks have to be terminated locally 
- create a new protocol for tunneling TCP and UDP over a single TLS
  or Quic connection.
- Distinct UDP flows to same destination will use distinct TCP/TLS
  connections. But, in theory could reuse the same Quic connection
  but with independent bi-dir streams
- The remote end of the tunnel have to support three kinds of
  backend:

    * TCP to well known downstream endpoint (with optional
      proxy-proto-v2)
    * UDP to well known downstream endpoint
    * Dynamic - where the downstream endpoint is in the first few
      bytes of a newly established connection or quic stream


Correspondingly, our conf file for supporting UDP looks
approximately like so:

```
listen tcp eth0:2080 socks udp 4000-5000
    timeout TIMEOUT-A ratelimit RL-A
    connect quic server.name:9080 from ip.addr.ess
```

Here, the `udp` keyword indicates that the
listening server will use a random port from the range
4000-5000 on interface eth0 in the BIND-ADDR:BIND-PORT
response to the UDP-ASSOCIATE SOCKS message.

The server could use the same addr:port for a given client or
pick a new one for each SOCKS UDP-ASSOCIATE request.

In the example above - the goal is to handle both modalities
in the same code path. Once we terminate socks protocol on the
local-end of the tunnel, we then employ a simpl(er) protocol
over the tunnel to communicate the intended destination:port.

Note that the tunnel transport in the example above is quic. It
can just as well be vanilla TLS-over-TCP; the code needs to be
able handle both combinations (quic + tls).

The datagrams received by the BIND-ADDR:PORT will have SOCKS UDP
framing:

```
  u16: reserved
  u8:  frag# - current fragment #; for us this should be ZERO
  u8:  addr type: IPv4 (0x01), DNS name (0x03), IPv6 (0x03)
  [n]u8: Addr 4 or 16 depending on prev field
  u16: dest port
  []u8: data

```

In our implementation, we will use the following (approx)
framing:

```
    u32     checksum    checksum of everything below
    u8      proto       TCP |UDP
    u8      addrtype    v4 | v6 | name
    u16     port        dest port
    u16     addrlen     addr length
    u16     resv        reserved
    []u8    addr        length bytes of address
```

We use a checksum to ensure that the first N bytes are not
misinterpreted by a misconfigured remote server.


# Implementation Notes

* Socks is now only on the local instance; remote never has to do
  socks. This makes it easy to do dynamic UDP-ASSOCIATE on the
  local-end by reserving a range of ingress ports.

* must add a new UDP listener on the local side; remote will never
  listen on raw UDP ever. It will always be a tunnel - TLS or Quic.

* udp-over-tls and udp-over-quic datagram framing

* dynamic mode for remote - to account for socks and udp.
  NB: UDP+Socks implies two modalities:

   - client knows downstream address at the time of socks
     establishment
   - client doesn't know downstream address at the time of socks
     establishment

* lots more new tests. ugh.

