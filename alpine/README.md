# Scripts and info for running go-tunnel on Alpine Linux

If you want to run go-tunnel on [Alpine](https://alpinelinux.org),
this might help you:

* build static binary for linux (from the top dir):

    ./build -s --arch=linux-amd64

* copy the binary to somewhere on PATH - preferably /usr/bin

* copy `etc/gotun.conf` to `/etc/gotun/gotun.conf`

* copy `gotun.init` to `/etc/init.d/gotun`

* Enable this to run in  the right run-levels:

    rc-update add gotun

# TODO
1. Make a real alpine package out of this.
2. Write man page
