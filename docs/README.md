# Example Configurations for various scenarios

## TLS to TCP proxy with client authentication
If you want to have strong authentication of clients to access a
service behind the proxy, then the following configuration is a good
starting point:

```yaml

log: SYSLOG
loglevel: INFO

listen:
    - address: ip.address:lport
      ratelimit:
          global: 20000
          per-host: 50
          # LRU cache size for per-host rate limit
          cache-size: 50000

      tls:
          cert: /path/to/server.crt
          key: /path/to/server.key
          # ca can be a file containing multiple certs or a
          # directory containing ca certs
          ca: /path/to/ca.bundle

          client-cert: required
          client-ca:  /path/to/clientca.crt


      connect:
          address: host.name:port
          proxy-protocol: v1

```

Now, clients that have a valid cert/key pair can connect to to
`ip.address:lport` above. And if the cert/key pair is valid and
accepted by the proxy, the client will be connected to the backend
on `host.name:port`.

## Quic to TCP with client authentication
If you have a modern quic client (e.g., most chrome browsers) but
your service is still serving legacy TCP/TLS, `gotunnel` can help
bridge this protocol gap: configure it to listen on a quic port and
relay connections from client to the backend TCP/TLS service:

```yaml

log: SYSLOG
loglevel: INFO

listen:
    - address: ip.address:lport
      ratelimit:
          global: 20000
          per-host: 50

      tls:
          quic: true
          cert: /path/to/server.crt
          key: /path/to/server.key
          # ca can be a file containing multiple certs or a
          # directory containing ca certs
          ca: /path/to/ca.bundle

          clientcert: required
          clientca:  /path/to/clientca.crt


      connect:
          address: host.name:port
          proxy-protocol: v1
```

The configuration is essentially the same as the previous one - with
the addition of the **`quic: true`** setting. This setting forces
`gotunnel` to listen on a UDP port.
