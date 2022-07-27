package main

import (
	"flag"
	"fmt"
	"github.com/op/go-logging"
	"net"
	"os"
	"strings"
)

var (
	threads   uint
	checker   bool
	resolvers string
	domains   string
	wordlist  string
	loglevel  string
	logfile   string
	dnstest   string

	log = logging.MustGetLogger("DNS")
)

func init() {
	flag.BoolVar(&checker, "check", false, "Load NS IPs from stdin and return alive to stdout")
	flag.UintVar(&threads, "threads", 8, "Threads per task")
	flag.StringVar(&resolvers, "resolvers", "alive.txt", "File with NS IPs (for bruteforce mode)")
	flag.StringVar(&domains, "domains", "target.txt", "File with domains to bruteforce")
	flag.StringVar(&wordlist, "wordlist", "names.txt", "File with domain subnames")
	flag.StringVar(&loglevel, "loglevel", "ERROR", "Set logging level (DEBUG|ERROR|WARN|INFO)")
	flag.StringVar(&logfile, "logfile", "", "Set output log file. Default - stderr")
	flag.StringVar(&dnstest, "validate", "dns.msftncsi.com:131.107.255.255", "Validate DNS servers using this pair")
}

func main() {
	flag.Parse()

	level, err := logging.LogLevel(loglevel)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	logout := os.Stdout

	if logfile != "" {
		logout, err = os.OpenFile(logfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
		defer logout.Close()
	}

	logbackend := logging.NewBackendFormatter(
		logging.NewLogBackend(os.Stdout, "", 0),
		logging.MustStringFormatter(
			`%{time:00:00:00.0000} %{level:.1s} %{message}`,
		),
	)

	logging.SetBackend(logbackend)
	logging.SetLevel(level, "DNS")
	parts := strings.Split(dnstest, ":")
	if len(parts) != 2 {
		log.Error("Invalid DNS format")
		os.Exit(1)
	}
	ValidateDnsHostname = parts[0]
	ValidateDnsIp = net.ParseIP(parts[1])

	if checker {
		c := NewChecker(threads)
		c.FilterAliveFromStream(os.Stdin, os.Stdout)
	} else {
		searcher := NewDnsSearch(threads)
		log.Debug("Setup")
		err := searcher.Setup(wordlist, resolvers, domains)
		if err != nil {
			log.Error("Couldn't load: ", err)
			os.Exit(1)
		}
		log.Debug("Start")

		for h := range searcher.Search() {
			fmt.Println(h)
		}

		searcher.SaveWordlist()
	}
}
