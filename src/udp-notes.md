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

* Local server is in exactly one of two modes:
    - TCP with socks
    - TCP with static remote endpoints
    - In particular we don't support raw udp tunnels.

* Terminate socks on the local side
    - support socks only on local tcp endpoint; need config checks for this
    - tunnel can be TLC or Quic. quicdial.go and tcpdial.go have the right
      abstractions to support uniform dialer modalities in the server loop.
    - once socks is negotiated with client:
       * if udp-associate:
           - handoff to udp processing; udp-processor will invoke the dialer
           - fork goroutine to handle udp clients; track the goroutines via Server.wg
        * else
           - dial connection (TLS|Quic)
           - setup relay
           - relay processing has the same format:
                * send dest in hdr packet
                * followed by client data
                * only first response has reply header.

    - Remote service that accepts tls or quic has to implement appropriate
      exit checks: either dyanmic endpoints are allowed or they are not based
      on config file.

* local-to-remote dialers need a bit of work:
    - use AddrSpec to pass the outbound info; this means each dialer will 
      marshal and send the dest addr in a new TLS conn OR a quick-stream
    - the remote end should unmarshal, do the next hop dialing (as described below)
      and return success/failure. This means we need a response method as well

* cleanup socks handling
    - separate file documenting the bits (socks5.go)
    - methods here are called from TCP server; it ought to be part of TCPServer
    - TCPServer ought to have the necessary bits for udp port finding etc:
        * single list (rand.Shuffle()); two pointers: head, tail
        * list guarded by mutex (keep it simple)
        * track udp listener goroutines via parent wg

* Remote server modes:
    - TCP vs. TLS could be separate functions; socks5 termination only on
      TCP instance.
    - TLS/Quic in static mode: single dest endpoint: TCP dialer only
    - TLS in dyn mode: every conn looks for dest hdr; must support udp dialing
    - Quic and TLS could share udp handling - by having a common set of dialers:
        * TCP dialer
        * UDP dialer
    - It makes sense to separate these into diff files so its easy to follow?


TODO:
* Why can't downstream connections be TLS/Quic?
* Supporting raw local UDP listeners with 1:1 remote mapping?

