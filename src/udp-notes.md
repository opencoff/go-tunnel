# UDP processing notes

We have two kinds of UDP tunneling to consider:

1. Downstream UDP to a fixed endpoint:

   ```
   # remote server
   listen quic :4000 pki CERT-Z 
        ratelimit RL-Z timeout TIMEOUT-Z
        connect udp downstream.name:2000 

   # local server
   listen udp eth0:4000
        ratelimit RL-Z timeout TIMEOUT-Z
        connect quic remote.name:4000 pki CERT-Z
   ```

   Each new UDP connection from the client will create a new quic
   stream to the remote server - thus eliminating head-of-line
   blocking concerns for the clients.

2. The tunnel between local and remote could also be TLS (over TCP).
   In which case, this looks very much like case #1 above:

   ```
    # remote server
    listen tls :4000 pki CERT-Z 
       ratelimit RL-Z timeout TIMEOUT-Z
       connect udp downstream.name:2000 

    # local server
    listen udp eth0:4000
        ratelimit RL-Z timeout TIMEOUT-Z
        connect tls remote.name:4000 pki CERT-Z
   ```

   Here, UDP connections from the same client will (likely) be
   multiplexed on the same TLS stream. This will create head-of-line
   blocking for clients. 

   In both #1 and #2 above, the datagram will be "framed" with a
   2-byte length prefix.

3. Downstream UDP via SOCKS; this has two modalities:
   - client knows downstream address at the time of socks
     establishment
   - client doesn't know downstream address at the time of socks
     establishment

   ```
    # remote server
    listen quic eth0:4330 CERT-A timeout TIMEOUT-A
            ratelimit RL-A
            connect SOCKS udp-advertise eth0:4000-5000

    # local server - _must_ look like SOCKS/TCP
    listen tcp eth0:2080
        ratelimit RL-Z timeout TIMEOUT-Z
        connect quic remote.name:4330 pki CERT-A
   ```

   Here, the `udp-advertise` keyword indicates that the
   listening server will use a random port from the range
   4000-5000 on interface eth0 in the BIND-ADDR:BIND-PORT
   response to the UDP-ASSOCIATE SOCKS message.

   The server could use the same addr:port for a given client or
   pick a new one for each SOCKS UDP-ASSOCIATE request.

   In the example above - the goal is to handle both modalities
   in the same code path. Note that SOCKS could be running on TLS
   (instead of Quic) and thus, the server must provide a
   BIND-ADDR:PORT in the response for UDP-ASSOCIATE.

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

   In our implementation, the data consists of a 2-byte length field
   followed by the application data. The clients are advised to stay
   within the network MTU - since we don't handle retransmissions or
   fragment reassembly.


# Implementation Notes

* must implement proper SOCKS-UDP support on client & server.

* must add a new UDP listener on the local + remote side
  the remote end may also need to be dynamic - ie spin up new
  listeners based on response to UDP-ASSOCIATE.

* udp-over-tls and udp-over-quic datagram framing

* lots more new tests. ugh.

