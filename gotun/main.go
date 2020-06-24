// main.go -- main() for gotun
//
// Author: Sudhi Herle <sudhi@herle.net>
//
// This software does not come with any express or implied
// warranty; it is provided "as is". No claim  is made to its
// suitability for any purpose.

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"

	flag "github.com/opencoff/pflag"

	L "github.com/opencoff/go-logger"
)

// This will be filled in by "build"
var RepoVersion string = "UNDEFINED"
var Buildtime string = "UNDEFINED"
var ProductVersion string = "UNDEFINED"

// Network I/O buffer size
var BufSize uint = 65536

// Number of minutes of profile data to capture
// XXX Where should this be set? Config file??
const PROFILE_MINS = 30

// Interface for all proxies
type Proxy interface {
	Start()
	Stop()
}

func main() {
	// maxout concurrency
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Make sure any files we create are readable ONLY by us
	syscall.Umask(0077)

	debugFlag := flag.BoolP("debug", "d", false, "Run in debug mode")
	verFlag := flag.BoolP("version", "v", false, "Show version info and quit")
	flag.UintVarP(&BufSize, "io-bufsize", "B", BufSize, "Set network I/O buffer size to `b` bytes")

	usage := fmt.Sprintf("%s [options] config-file", os.Args[0])

	flag.Usage = func() {
		fmt.Printf("gotun - TCP/TLS and Quic Server/Proxy\nUsage: %s\n", usage)
		flag.PrintDefaults()
	}

	flag.Parse()

	if *verFlag {
		fmt.Printf("gotun - %s [%s; %s]\n", ProductVersion, RepoVersion, Buildtime)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		die("No config file!\nUsage: %s", usage)
	}

	cfgfile := args[0]
	cfg, err := ReadYAML(cfgfile)
	if err != nil {
		die("Can't read config file %s: %s", cfgfile, err)
	}

	prio, ok := L.ToPriority(cfg.LogLevel)
	if !ok {
		die("Invalid log-level %s", cfg.LogLevel)
	}

	// We want microsecond timestamps and debug logs to have short
	// filenames
	const logflags int = L.Ldate | L.Ltime | L.Lshortfile | L.Lmicroseconds
	var logf string = cfg.Logging

	if *debugFlag {
		prio = L.LOG_DEBUG
		logf = "STDOUT"
	}

	log, err := L.NewLogger(logf, prio, "gotun", logflags)
	if err != nil {
		die("Can't create logger: %s", err)
	}

	err = log.EnableRotation(00, 01, 00, 7)
	if err != nil {
		warn("Can't enable log rotation: %s", err)
	}

	log.Info("gotun - %s [%s - built on %s] starting up (logging at %s)...",
		ProductVersion, RepoVersion, Buildtime, log.Prio())

	cfg.Dump(log)

	if len(cfg.Listen) == 0 {
		die("%s: no listeners in config file", cfgfile)
	}

	if *debugFlag {
		cfg.Dump(os.Stdout)
	}

	var srv []Proxy
	for _, ln := range cfg.Listen {
		p := NewServer(ln, cfg, log)
		srv = append(srv, p)
	}

	// Drop privileges before starting each server
	DropPrivilege(cfg.Uid, cfg.Gid)

	for _, s := range srv {
		s.Start()
	}

	// Setup signal handlers
	sigchan := make(chan os.Signal, 4)
	signal.Notify(sigchan,
		syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	signal.Ignore(syscall.SIGPIPE, syscall.SIGFPE)

	// Now wait for signals to arrive
	for {
		s := <-sigchan
		t := s.(syscall.Signal)

		log.Info("Caught signal %d; Terminating ..\n", int(t))
		break
	}

	for _, s := range srv {
		s.Stop()
	}

	log.Info("Shutdown complete!")

	// Finally, close the logging subsystem
	log.Close()
	os.Exit(0)
}

// Profiler
func initProfilers(log *L.Logger, dbdir string) {
	cpuf := fmt.Sprintf("%s/cpu.cprof", dbdir)
	memf := fmt.Sprintf("%s/mem.mprof", dbdir)

	cfd, err := os.OpenFile(cpuf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0600)
	if err != nil {
		die("Can't create %s: %s", cpuf, err)
	}

	mfd, err := os.OpenFile(memf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_SYNC, 0600)
	if err != nil {
		die("Can't create %s: %s", memf, err)
	}

	log.Info("Starting CPU & Mem Profiler (first %d mins of execution)..", PROFILE_MINS)

	pprof.StartCPUProfile(cfd)
	time.AfterFunc(PROFILE_MINS*time.Minute, func() {
		pprof.StopCPUProfile()
		cfd.Close()
		log.Info("Ending CPU profiler..")
	})

	time.AfterFunc(PROFILE_MINS*time.Minute, func() {
		pprof.WriteHeapProfile(mfd)
		mfd.Close()
		log.Info("Ending Mem profiler..")
	})
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=88:
