# go-tunnel - Robust TLS Tunnel (Stunnel replacement)

## What is it?
An [Stunnel](https://www.stunnel.org) replacement written in golang. It is
is in a sense a proxy enabling addition of network-encryption to existing
clients without any source code changes.

go-tunnel uses golang's TLS stack and built-in certification verification.

## Features

- TLS 1.2 for client and server mode (TLS Connect or TLS Listen)
- Optional TLS client certificate (for TLS Connect)
- SNI on the listening TLS server
- Ratelimits - global and per-IP
- [Proxy-Protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
  v1 support when connecting to downstream servers
- YAML Configuration file
- Access Control on per IP or subnet basis (allow/deny combination)
- Strong ciphers and curves preferred on both client & server

### Motivating Example
Let us suppose that you have a SOCKS5 server on host `192.168.55.3` and this
is accessible via a "gateway" node `172.16.55.3`. Furthermore, let us say that
clients/browsers wishing to use the SOCKS5 proxy are in the `10.0.0.0/24` subnet.
And to keep things simple, let us assume that one host in the `10.0.0.0` network 
can access the gateway node: `10.0.0.5`.

Ordinarily, we'd create a IP routing rule on `10.0.0.5` to make the hosts on its network
access the `192.168.55.0/24` via `172.16.55.3`. But, we desire the communication
between `10.0.0.0/24` and `172.16.55.0/24` to be encrypted.

Thus, with go-tunnel, one can setup a "bridge" between the two networks - and the bridge
is encrypted with TLS. The picture below explains the connectivity:

![example diagram](/docs/example-diagram.png)

In the setup above, hosts will treat `10.0.0.5:1080` as their "real" SOCKS server. Behind the
scenes, go-tunnel is relaying the packets from `10.0.0.5` to `172.16.55.3` via TLS. And, in turn
`172.16.55.3` relays the decrypted packets to the actual SOCKS server on `192.168.55.3`.

The config file shown above actually demonstrates a really secure tunnel - where the server and
client both use certificates to authenticate each other.

Assuming the config on "Gotunnel-A" is in file `a.conf`, and the config on "Gotunnel-B" is in 
`b.conf`, to run the above example, on host "Gotunnel-A":

    gotun -d a.conf

And, on host "Gotunnel-B":

    gotun -d b.conf


The `-d` flag runs `gotun` in debug mode - where the logs are sent
to STDOUT.

### Building go-tunnel
You need a reasonably new Golang toolchain (1.8+). And the `go`
executable needs to be in your path. Then run:

    make

Make essentially runs two tools as a convenience:

    ./dep.sh ensure
    ./build

`dep.sh` will download the vendor dependencies into the `vendor/src`
directory. These dependencies are named in `vendor/manifest.txt`.

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

### Config File
The config file is a YAML v2 document. An example is below:
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

# Listeners
listen:
    # Listen plain text
    -   address: 127.0.0.1:9090
        allow: [127.0.0.1/8, 11.0.1.0/24, 11.0.2.0/24]
        deny: []

        timeout:
            connect: 10
            read: 10
            write: 30

        # limit to N reqs/sec globally
        ratelimit:
            global: 2000
            perhost: 30

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
            connect: 8
            read: 9
            write: 27

        tls:
            sni: true
            certdir: /path/to/cert/dir

            # clientcert can be "required" or "optional" or "blank" or absent.
            # if it is required/optional, then clientca must be set to the list of
            # CAs that can verify a presented client cert.
            clientcert: required
            clientca: /path/to/clientca.crt

        # plain connect but use proxy-protocol v1 when speaking
        # downstream
        connect:
            address: 55.66.77.88:80
            proxyprotocol: v1

```

### Examples
TBD

### Performance Test
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

### Access Control Rules
Go-tunnel implements a flexible ACL by combination of
allow/deny rules. The rules are evaluated in the following order:

- If explicitly denied, then host is blocked
- If allow list is empty, then host is allowed
- If allow list is non-empty & host is in allow-list, then host is allowed
- Explicit denial takes precedence over explicit allow
- Default (fall through) policy is to deny

#### Example of allow/deny combinations

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

- The code is written in go. We use vendor branch support to manage
  3rd party repositories.

- The code layout is as follows:

  - vendor code in `./vendor`
  - go-tunnel code in `./src/gotun`

- GOPATH is set by `dep.sh` and `build` to: `$PWD/vendor:$PWD`. This means that
  `go` toolchain will look for source code references *first* in `$PWD/src` then
  in `$PWD/vendor/src`.

- We build using two scripts:

   - `dep.sh` -- described below
   - `build`  -- a master shell script to build the daemons; it does two very
     important things: Puts the binary in an OS/Arch specific directory and
     injects a git version-tag into the final binary ("linker resolved symbol").
     This script can be reused for other go projects.

- If you are building for the first time, then you have to first prepare the 3rd
  party vendored code:

```
     ./dep.sh ensure
```

  This pulls in the required 3rd party libraries and checks out the pinned
  versions. The list of 3rd party dependencies are in `vendor/manifest.txt`.
  This file is automatically generated by the `dep.sh` script.

- Example config files is in the `etc/gotun.conf` directory.

- Each daemon uses a set of common "local" libraries -- i.e., libraries that are
  meaningful only to the daemons. These are in the `src/lib/` sub-dirs. In Go,
  these are imported like so (for example):

```golang
    import "lib/config"
```

- Vendor libraries from github are imported using the `dep.sh` script like so:

```
    ./dep.sh get github.com/opencoff/go-ratelimit
```

  And used in code using the usual syntax. The above command fetches the library
  and its dependencies and records them in `vendor/manifest.txt`.

### What is `dep.sh`
`dep.sh` is a simple vendor management tool for go. It does **NOT** checkin
the vendor code into your repository. This keeps your repository small & clean.
It is in its own github repository: [dep.sh](https://github.com/opencoff/dep.sh)

`dep.sh` is written entirely as a portable (bash) shell-script.

When run from a directory, it implicitly sets `GOPATH` to `$PWD/vendor:$PWD`.
This allows one to structure the code as follows:

- All vendored code goes in `./vendor/src`
- All local code goes in sub directories of `./src`
- All local libraries (by convention) go in `./src/lib`; and imported in code
  as:

```golang
    import "lib/module"
```

General usage help:

    ./dep.sh --help

`dep.sh` adds the following commands to the tool-chain vocabulary:

- `fetch`, `get` -- fetch and record a new vendor dependency.

- `update` -- update one repository from upstream or *all* repositories from
  upstream and update the manifest.

- `sync`, `ensure` -- prepare the local directory with the correct checked out version of
  the vendor dependency. This must be run _once_ when a new directory is setup for
  building the entire daemon.

- `list` -- show list of vendored code and its locked versions.

#### Vendor Management
Vendor dependencies are recorded in the file `vendor/manifest.txt`. Each line is
either a comment (starts with '#') or is a dependency record. Each record is a
3-tuple of import-path, upstream-URL, pinned-version.

`dep.sh get` and `dep.sh update` update the manifest. `dep.sh ensure` consults the
manifest to checkout the correct version.

The checked out vendor code follows the Golang vendor conventions: the code is put
in `vendor/src`.


