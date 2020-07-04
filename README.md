# go-tunnel - Robust Quic/TLS Tunnel (Stunnel replacement)

## What is it?
A supercharged [Stunnel](https://www.stunnel.org) replacement written in golang.
is in a sense a proxy enabling addition of network-encryption to existing
clients without any source code changes.

## Features

- TLS 1.3 for client and server mode (TLS Connect or TLS Listen)
- Quic client and server mode (Quic listen or Quic connect)
- Optional SOCKS for connecting endpoint (SOCKS server)
- Optional TLS client certificate (for Quic/TLS Connect)
- SNI on the listening Quic/TLS server
- Ratelimits - global and per-IP
- [Proxy-Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
  v1 support when connecting to downstream servers
- YAML Configuration file
- Access Control on per IP or subnet basis (allow/deny combination)
- Strong ciphers and curves preferred on both client & server
- Comes with end-to-end tests covering variety of scenarios

Note that TLS private keys need to be *unencrypted*; we don't support password protected
private keys yet. The main reason for this is that when `gotun` is daemonized, it may not be
possible to obtain the password in an interactive manner. Additionally, for SNI support, it may be
impossible to ask for interactive password in the middle of a client connection setup.

## Motivating Example
Lets assume you have a public server on `proxy.example.com`
listening on Quic/UDP supporting SOCKS protocol for connecting to
outbound destinations. For security reasons, you want to limit
access to only clients that are TLS authenticated (TLS client
certs).

Lets also assume that you have a laptop that wants to connect to the
SOCKS server efficiently.

Using two instances of `gotun`, you can accomplish this:

1. Local gotun instance on your laptop configured to accept TCP and
   connect using Quic to the external server `proxy.example.com`

2. Server gotun instance on the external host configured to accept
   authenticated Quic connections and proxy via SOCKS.

3. Configure your laptop browser to use the "local" SOCKS server.

Using Quic to connect the two `gotun` instances reduces the TCP/TLS
overhead of every socks connection. And, TLS client certs enables
strong authentication on the external server.

The picture below explains the connectivity:

![example diagram](/docs/socks-example.png)

In the setup above, the laptop browser clients will treat
`127.0.0.1:1080` as their "real" SOCKS server. Behind the scenes,
`gotun` will tunnel the packets via Quic to a remote endpoint where
a second `gotun` instance will unbundle the SOCKS protocol and
connect to the final destination.

The config file shown above actually demonstrates a really secure tunnel
where the server and client both use certificates to authenticate each other.

Assuming the config on "Gotunnel Laptop" is in file `client.conf`, and the
config on "Gotunnel Server" is in `server.conf`, to run the above example,
on host "Gotunnel-A":

    gotun client.conf

And, on the public server:

    gotun server.conf

The `-d` flag for `gotun` runs it in debug mode - where the logs are sent
to STDOUT. It's not recommended to run a production server in debug
mode (too many log messages).

## Building go-tunnel
You need a reasonably new Golang toolchain (1.14+). And the `go`
executable needs to be in your path. Then run:

    make

Make essentially runs:

    ./build

`build` will build the binary `gotun` and places it in TARGET specific
directory. e.g., for linux-amd64, the binaries will be in `./bin/linux-amd64`;
and OS X, it will be in `./bin/darwin-amd64` and so on.

You can cross-compile 'go-tun' by passing appropriate architecture names to
the script. e.g., to build on host OS X for openbsd-amd64:

    ./build --arch=openbsd-amd64

You can build a statically linked executable (with no other runtime dependency):

    ./build -s

The script also has other options. To see them::

    ./build --help


### Running go-tunnel
`gotun` takes a YAML config file as its sole command line argument. The server
does *not* fork itself into the background. If you need that capability, explore your
platform's init toolchain (e.g., `start-stop-daemon`).

The server can run in debug mode; e.g., on Linux x86\_64:

    ./bin/linux-amd64/gotun -d etc/gotun.conf


In debug mode, the logs are sent to STDOUT and the debug level is set to DEBUG
(i.e., verbose).

In the absence of the `-d` flag, the default log level is INFO or
whatever is set in the config file.

## Config File
The config file is a YAML v2 document. A complete, self-explanatory example is below:

```yaml

# Log file; can be one of:
#  - Absolute path
#  - SYSLOG
#  - STDOUT
#  - STDERR
log: STDOUT
#log: STDOUT

# Logging level - "DEBUG", "INFO", "WARN", "ERROR"
loglevel: DEBUG

# config dir - where all non-absolute file references below will
# apply.
config-dir: /etc/gotun

# Listeners
listen:
    # Listen plain text
    -   address: 127.0.0.1:9090
        allow: [127.0.0.1/8, 11.0.1.0/24, 11.0.2.0/24]
        deny: []

        timeout:
            connect: 5
            read: 2
            write: 2

        # limit to N reqs/sec globally
        ratelimit:
            global: 2000
            per-host: 30
            cache-size: 10000

        # Connect via TLS
        connect:
            address: host.name:443
            bind: my.ip.address
            tls:
                cert: /path/to/crt
                key: /path/to/key
                # path to CA bundle that can verify the server certificate.
                # This can be a file or a directory.
                ca: /path/to/ca.crt

            # if address is a name, then servername is populated from it.
            # else, if it is an IP address, it must be set below.
            # Not setting it => no verification (InsecureSkipVerify = true)
            # servername: a.example.com

    # Listen using TLS with SNI
    -   address: 127.0.0.1:9443
        allow: [127.0.0.1/8, 11.0.1.0/24, 11.0.2.0/24]
        deny: []
        timeout:
            connect: 5
            read: 2
            write: 2

        tls:
            sni: /path/to/cert/dir

            # clientcert can be "required" or "optional" or "blank" or absent.
            # if it is required/optional, then clientca must be set to the list of
            # CAs that can verify a presented client cert.
            client-cert: required
            client-ca: /path/to/clientca.crt

        # plain connect but use proxy-protocol v1 when speaking
        # downstream
        connect:
            address: 55.66.77.88:80
            proxyprotocol: v1


    # Listen on Quic + client auth and connect to SOCKS
    -   address: 127.0.0.1:8443
        tls:
            quic: true
            cert: /path/to/crt
            key: /path/to/key
            # path to CA bundle that can verify the server certificate.
            # This can be a file or a directory.
            ca: /path/to/ca.crt

            client-cert: required
            client-ca: /path/to/clientca.crt

        connect:
            address: SOCKS

```

The `etc/` directory has example configurations for running
Quic+SOCKS on a public server and a local laptop.

## Using SNI
SNI is exposed via domain specific certs & keys in the `tls.certdir` config block. SNI is
enabled by setting `tls.sni` config element to `true`; and each hostname that is requested via
SNI needs a cert and key file with the file prefix of hostname. e.g., if the client is looking
for hostname "blog.mydomain.com" via SNI, then `gotun` will look for `blog.mydomain.com.crt` and
`blog.mydomain.com.key` in the directory identified by `tls.certdir`. The config file above has
an example for SNI configured on listen address `127.0.0.1:9443`.

## Generating Local Certificates
If you want client authentication and don't want the hassle of using
openssl or a commercial CA for obtaining the certs, you can use
[certik]((https://github.com/opencoff/certik) to create an easy,
opinionated local CA infrastucture. Assuming you are on a
linux-amd64 platform:

```sh

$ git clone https://github.com/opencoff/certik
$ cd certik
$ ./build -s
$ ./bin/linux-amd64/certik ca.db init "client CA" 
$ ./bin/linux-amd64/certik ca.db user username@example.com
$ ./bin/linux-amd64/certik ca.db export -o ca --ca
$ ./bin/linux-amd64/certik ca.db export -o username username@example.com

```

Now, you have `ca.crt` as the CA root of trust for the Quic server
to validate client certs. And, the client cert/key for
`username@example.com` is in `username.crt` and `username.key`

You can copy and use `ca.crt` and user's cert/key to `gotun` config directory
and refer to it in the config file under "client-ca" and "tls.cert",
"tls.key" respectively.

## Security
`gotun` tries to be safe by default:

- Opinionated TLS 1.3 configuration
- All config file references are checked for safety: e.g., any TLS
  certs/keys are verified to have sane permissions (NOT group/world
  writable)

## Performance Test
Using iperf3 on two debian-linux (amd64) hosts connected via Gigabit Ethernet and `gotun` running on either end,
the performance looks like so:

```shell
$ iperf3 -V  -c 127.0.0.1 -p 9000
iperf 3.1.3
Linux ungoliant 4.15.0-2-amd64 #1 SMP Debian 4.15.11-1 (2018-03-20) x86_64
Time: Sat, 28 Apr 2018 21:18:46 GMT
Connecting to host 127.0.0.1, port 9000
      Cookie: ungoliant.1524950326.966562.77625193
      TCP MSS: 21888 (default)
[  4] local 127.0.0.1 port 35444 connected to 127.0.0.1 port 9000
Starting Test: protocol: TCP, 1 streams, 131072 byte blocks, omitting 0 seconds, 10 second test
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec  54.5 MBytes   457 Mbits/sec    0   2.50 MBytes
[  4]   1.00-2.00   sec  45.7 MBytes   383 Mbits/sec    0   2.50 MBytes
[  4]   2.00-3.00   sec  46.2 MBytes   388 Mbits/sec    0   2.50 MBytes
[  4]   3.00-4.00   sec  46.5 MBytes   390 Mbits/sec    0   2.50 MBytes
[  4]   4.00-5.00   sec  46.6 MBytes   391 Mbits/sec    0   2.50 MBytes
[  4]   5.00-6.00   sec  46.2 MBytes   388 Mbits/sec    0   2.50 MBytes
[  4]   6.00-7.00   sec  47.0 MBytes   394 Mbits/sec    0   2.50 MBytes
[  4]   7.00-8.00   sec  47.7 MBytes   400 Mbits/sec    0   2.50 MBytes
[  4]   8.00-9.00   sec  47.5 MBytes   398 Mbits/sec    0   2.50 MBytes
[  4]   9.00-10.00  sec  46.7 MBytes   392 Mbits/sec    0   2.50 MBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
Test Complete. Summary Results:
[ ID] Interval           Transfer     Bandwidth       Retr
[  4]   0.00-10.00  sec   475 MBytes   398 Mbits/sec    0             sender
[  4]   0.00-10.00  sec   464 MBytes   389 Mbits/sec                  receiver
CPU Utilization: local/sender 1.8% (0.0%u/1.7%s), remote/receiver 9.0% (0.6%u/8.4%s)

```

## Access Control Rules
Go-tunnel implements a flexible ACL by combination of
allow/deny rules. The rules are evaluated in the following order:

- If explicitly denied, then host is blocked
- If allow list is empty, then host is allowed
- If allow list is non-empty & host is in allow-list, then host is allowed
- Explicit denial takes precedence over explicit allow
- Default (fall through) policy is to deny

### Example of allow/deny combinations

1. Allow all:

```yaml
   allow: []
   deny:  []
```

2. Only allow specific subnets and deny everyone else:

```yaml
    allow: [ 192.168.55.0/24, 172.16.10.0/24, 127.0.0.1/8 ]
    deny: []
```


3. Allow all except selected subnets:

```yaml
    allow: []
    deny: [ 192.168.80.0/24, 172.16.5.0/24 ]
```


4. Expliclty block certain hosts and explicitly allow certain
   subnets and block everyone else:

```yaml
    allow: [ 192.168.55.0/24, 172.16.10.0/24, 127.0.0.1/8 ]
    deny:  [ 192.168.1.1/32, 192.168.80.0/24, 172.16.5.0/24 ]
```


## Development Notes
If you are a developer, the notes here will be useful for you:

- The code uses go modules; so, you'll need a reasonably new go toolchain (1.10+)

- The go-tunnel code is in `./gotun`:

    * main.go: `main()` for `gotun`
    * server.go: Implements TCP/TLS and Quic servers; also
      implements the SOCKS server protocol
    * conf.go: YAML configuration file parser
    * quicdial.go: Dial outbound connections via Quic + streams
    * tcpdial.go: Dial outbound connections via TCP
    * safety.go: Safely open files/dirs referenced in config file

- Tests: running tests: `go test -v ./gotun`
  Some of the tests/helpers:
    * mocked_test.go: Mock servers and clients
    * tcp_test.go: Tests for TCP/TLS to TCP/TLS
    * quic_test.go: Tests for TCP/TLS to Quic and vice versa
    * socks_test.go: Tests for socks (includes a test for the
      example configuration above)
    * utils_test.go: test helpers (e.g., `assert()`)

- We build `build` - a a master shell script to build the daemons;
  it does two very important things:

    * Puts the binary in an OS/Arch specific directory
    * Injects a git version-tag into the final binary ("linker resolved symbol")

  This script can be reused for other go projects.

- Example config files is in the `etc/gotun.conf` directory.



