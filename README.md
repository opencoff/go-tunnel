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
- YAML Configuration file
- Access Control on per IP or subnet basis (allow/deny combination)

### Modes of operation
TBD with Pictures

### Building go-tunnel
You need a reasonably new Golang toolchain (1.8+). And the `go`
executable needs to be in your path. Then run:

    ./build

The script will build the binary `gotun` and places it in TARGET specific
directory. e.g., for linux-amd64, the binaries will be in `./bin/linux-amd64`;
and OS X, it will be in `./bin/darwin-amd64` and so on.

You can cross-compile by passing appropriate architecture names to
the script. e.g., to build on host OS X for openbsd-amd64:

    ./build --arch=openbsd-amd64

You can build a statically linked executable (with no other runtime dependency):

    ./build -s

The script also has other options. To see them::

    ./build --help


### Config File
The config file is a YAML v2 document. An example is below:

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

		# plain connect
		connect:
		    address: 55.66.77.88:80

	    -   address: 127.0.0.1:465
		deny: []
		tls:
		    cert: /path/to/a.crt
		    key: /path/to/a.key


### Examples
TBD

### Access Control Rules
Go-tunnel implements a flexible ACL by combination of
allow/deny rules. The rules are evaluated in the following order:

- If explicitly denied, the host is blocked
- If explicitly allowed, the host is allowed
- Explicit denial takes precedence over explicit allow
- Empty allow list is the same as "allow all"

#### Example of allow/deny combinations

1. Only allow specific subnets and deny everyone else:

    allow: [ 192.168.55.0/24, 172.16.10.0/24, 127.0.0.1/8 ],
    deny: []


2. Allow all except selected subnets:

    allow: [],
    deny: [ 192.168.80.0/24", 172.16.5.0/24 ]


3. Expliclty block certain hosts and explicitly allow certain
   subnets and block everyone else:

    allow: [ 192.168.55.0/24, 172.16.10.0/24, 127.0.0.1/8 ],
    deny:  [ 192.168.1.1/32, 192.168.80.0/24, 172.16.5.0/24 ]


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

     ./dep.sh ensure

  This pulls in the required 3rd party libraries and checks out the pinned
  versions. The list of 3rd party dependencies are in `vendor/manifest.txt`.
  This file is automatically generated by the `dep.sh` script.

- Example config files is in the `etc/gotun.conf` directory.

- Each daemon uses a set of common "local" libraries -- i.e., libraries that are
  meaningful only to the daemons. These are in the `src/lib/` sub-dirs. In Go,
  these are imported like so (for example):

    import "lib/config"

- Vendor libraries from github are imported using the `dep.sh` script like so:

    ./dep.sh get github.com/opencoff/go-ratelimit

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

    import "lib/module"

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


