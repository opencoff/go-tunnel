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
	"strings"
	"syscall"
	"time"

	flag "github.com/ogier/pflag"

	L "github.com/opencoff/go-logger"
)

// This will be filled in by "build"
var RepoVersion string = "UNDEFINED"
var Buildtime string = "UNDEFINED"
var ProductVersion string = "UNDEFINED"

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

	usage := fmt.Sprintf("%s [options] config-file", os.Args[0])

	flag.Usage = func() {
		fmt.Printf("gotun - TLS Tunneler\nUsage: %s\n", usage)
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

	// We want microsecond timestamps and debug logs to have short
	// filenames
	const logflags int = L.Ldate | L.Ltime | L.Lshortfile | L.Lmicroseconds
	prio := L.LOG_DEBUG
	logf := "STDOUT"

	if !*debugFlag {
		var ok bool

		lvl := strings.ToUpper(cfg.LogLevel)
		prio, ok = L.PrioName[lvl]
		if !ok {
			die("Unknown log level %s", lvl)
		}

		logf = cfg.Logging
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
		ProductVersion, RepoVersion, Buildtime, L.PrioString[log.Prio()])

	cfg.Dump(log)

	if len(cfg.Listen) == 0 {
		die("%s: no listeners in config file", cfgfile)
	}

	var srv []Proxy
	for _, ln := range cfg.Listen {
		p := NewTCPServer(ln, log)
		srv = append(srv, p)
		p.Start()
	}

	// Setup signal handlers
	sigchan := make(chan os.Signal, 4)
	signal.Notify(sigchan,
		syscall.SIGTERM, syscall.SIGKILL,
		syscall.SIGINT, syscall.SIGHUP)

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
