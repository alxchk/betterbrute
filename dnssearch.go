package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	ClientWordGenerator uint8 = iota + 1
	ClientValidator
	ClientResolver

	CliendLocked uint8 = iota + 1
	ClientUnlocked
	ClientNew
	ClientComplete
)

var (
	Blacklist []string = []string{
		".akadns.net",
		".akamaiedge.net",
		".amazonaws.com",
		".amazon.com",
		".awsdns-",
		".cdn.cloudn",
		".cdnetworks.net",
		".cdngc.net",
		".cloudfront.net",
		".edgekey.net",
		".edgesuite.net",
		".lldns.net",
	}
)

type (
	DnsSearch struct {
		wordlist      *ReplayStorage
		resolver      *Resolver
		domains       []string
		threads       uint
		wordlist_path string
	}

	dnsSearchContext struct {
		out        chan string
		hostnames  <-chan string
		tovalidate chan string
		toresolve  chan *DnsRequest
		badhost    chan *DnsRequest
		resolved   <-chan *DnsResponse
		validated  <-chan *DnsResponse
		generator  *HostnameGenerator
		pending    int32
	}

	HostnameGenerator struct {
		domains   []string
		update    *sync.RWMutex
		wordlist  *ReplayStorage
		generator chan string
		active    []bool
	}
)

func NewDnsSearch(threads uint) *DnsSearch {
	return &DnsSearch{
		threads:  threads,
		wordlist: NewReplayStorage(),
		resolver: NewResolver(threads),
	}
}

func (d *DnsSearch) Setup(wordlist, nameservers, domains string) error {
	err := d.resolver.AddNsFromList(nameservers)
	if err != nil {
		return err
	}

	wfile, err := os.Open(wordlist)
	if err != nil {
		return err
	}
	defer wfile.Close()

	d.wordlist_path = wordlist

	words := make([]interface{}, 0)

	reader := bufio.NewScanner(wfile)
	for reader.Scan() {
		words = append(words, reader.Text())
	}

	d.wordlist.Add(words...)

	dfile, err := os.Open(domains)
	if err != nil {
		return err
	}

	defer dfile.Close()

	reader = bufio.NewScanner(dfile)
	for reader.Scan() {
		d.domains = append(d.domains, reader.Text())
	}

	return nil
}

func NewHostnameGenerator(wordlist *ReplayStorage) *HostnameGenerator {
	w := &HostnameGenerator{
		wordlist:  wordlist,
		generator: make(chan string),
		update:    new(sync.RWMutex),
	}

	return w
}

func (g *HostnameGenerator) Iterator() <-chan string {
	return g.generator
}

func (g *HostnameGenerator) Close() {
	g.wordlist.Close()
	close(g.generator)
}

func (g *HostnameGenerator) loop(idx uint, hostname string) {
	g.generator <- hostname

	for word := range g.wordlist.Iterator() {
		if word == nil {
			log.Debug("% [G] WORDLIST: WILL BLOCK")
			g.update.Lock()
			g.active[idx] = false
			g.update.Unlock()
			continue
		}

		g.update.Lock()
		if !g.active[idx] {
			log.Debug("% [G] WORDLIST: NOT BLOCK")
			g.active[idx] = true
		}
		g.update.Unlock()

		host := word.(string) + "." + hostname
		log.Info("> [G] QUERY: ", host, " START")

		g.generator <- host
		log.Info("> [G] QUERY: ", host, " COMPLETE")
	}
	log.Debug("@ [G] COMPLETE")
}

func (g *HostnameGenerator) Run(host string) bool {
	g.update.Lock()
	defer g.update.Unlock()

	for _, domain := range g.domains {
		if domain == host {
			return false
		}
	}

	g.active = append(g.active, true)
	g.domains = append(g.domains, host)

	log.Debug("% GROUP RESOURCES ADD: +1")
	go g.loop(uint(len(g.active)-1), host)
	return true
}

func (g *HostnameGenerator) Blocked() bool {
	g.update.Lock()
	defer g.update.Unlock()

	for _, v := range g.active {
		if v {
			return false
		}
	}

	return true
}

func (d *DnsSearch) enumerationLoop(idx uint, ctx *dnsSearchContext) {
	var hostnames <-chan string = ctx.hostnames

	var tovalidate chan string = nil
	var tovalidate_value string

	var toresolve chan *DnsRequest = nil
	var toresolve_value *DnsRequest = nil
	var toresolve_hostname string

	var ok bool

mainloop:
	for {
		altered := false

		log.Debug(idx, "-----> ENUMERATION LOOP")
		select {
		case toresolve_hostname, ok = <-hostnames:
			if !ok {
				break mainloop
			}

			log.Debug(idx, "[<] Hostname: ", toresolve_hostname, " - begin")
			log.Debug(idx, "[<] Hostname: Pending: ", atomic.AddInt32(&ctx.pending, 1))
			toresolve_value = HostnameRequest(toresolve_hostname)
			toresolve = ctx.toresolve
			hostnames = nil

		case toresolve <- toresolve_value:
			log.Debug(idx, "[<] Hostname: ", toresolve_value, " - complete")
			toresolve = nil

		case tovalidate <- tovalidate_value:
			log.Debug(idx, "> [G -> V] Validate found host: ", tovalidate_value, " - complete")
			tovalidate = nil

		case r := <-ctx.resolved:
			subrequest := false

			log.Debug(idx, "| [G] #1. QUERY: ", r.Host)

			if !(r.Info == nil || r.Info.Empty() || r.Info.Axfr) {
				log.Debug(idx, "| [G] #2. QUERY: ", r.Host, ": Parse response")

				subdomains := []string{}
				words := []string{}

				for _, ns := range r.Info.Ns {
					subdomains = append(subdomains, ns)
				}

				for _, mx := range r.Info.Mx {
					subdomains = append(subdomains, mx)
				}

				for _, cname := range r.Info.Cname {
					subdomains = append(subdomains, cname)
				}

			filterloop:
				for _, host := range subdomains {
					for _, b := range Blacklist {
						if strings.Contains(host, b) {
							continue filterloop
						}
					}

					idx := strings.LastIndex(host, "."+r.Host)
					if idx != -1 {
						host = host[:idx]
					}

					for _, part := range strings.Split(host, ".") {
						if part == "" || part == " " {
							continue
						}

						idx := sort.SearchStrings(words, part)
						if idx >= len(words) {
							words = append(words, part)
						} else {
							if words[idx] != part {
								words = append(append(words[:idx], part), words[idx+1:]...)
							}
						}
					}
				}

				log.Debug(idx, "| [G] #3. QUERY: ", r.Host, ": Add subdomains (", words, "); Serial: ",
					r.Info.Serial)

				interfaces := make([]interface{}, len(words))
				for i := range words {
					interfaces[i] = words[i]
				}

				if d.wordlist.AddUniq(interfaces...) {
					altered = true
				}
				log.Debug(idx, "| [G] #4. QUERY: ", r.Host, ": Add subdomains (", len(words), ") - Complete")

				found := false
				if r.Info.Serial > 0 {
					log.Debug(idx, "| #5. [G] QUERY: ", r.Host, ": Serial found: ", r.Info.Serial)
					for _, cname := range r.Info.Cname {
						strings.Contains(r.Host, cname)
						log.Debug(idx, "| #5.1. CNAME IN HOSTNAME: ", r.Host, cname)
						found = true
						break
					}
					if !found {
						log.Debug(idx, "> #6. [G -> V] Validate found host: ", r.Host, ", Ns: ", r.Info.SoaNs)
						atomic.AddInt32(&ctx.pending, 1)
						tovalidate_value = r.Host
						tovalidate = ctx.tovalidate

						if r.Info.SoaNs != "" {
							log.Debug(idx, "> #7. Resolve AXFR: ", r.Host, "@", r.Info.SoaNs)
							atomic.AddInt32(&ctx.pending, 1)
							toresolve_value = AxfrRequest(r.Host, r.Info.SoaNs)
							toresolve = ctx.toresolve
							subrequest = true
						}
					}
				}

				log.Debug(idx, "> #8. [G -> R] Report result - begin")
				ctx.out <- r.String()
				log.Debug(idx, "> #9. [G -> R] Report result - complete")
			} else if r.Error != nil {
				log.Debug(idx, "! #10. [R] Filter result ", r)
			} else if r.Info != nil && r.Error == nil && r.Info.Axfr {
				ctx.out <- r.String()
			} else {
				log.Debug(idx, "| #11. [G] QUERY: ", r.Host, " -- EMPTY")
			}

			// log.Debug(idx, "[>] Hostname: Pending: ", atomic.AddInt32(&ctx.pending, -1))

			if atomic.AddInt32(&ctx.pending, -1) == 0 && altered == false && ctx.generator.Blocked() {
				ctx.generator.Close()
				close(ctx.out)
				log.Warning(idx, "THREADS COMPLETE")
			}

			log.Debug(idx, "CURRENT: ",
				altered, atomic.LoadInt32(&ctx.pending), ctx.generator.Blocked())

			if !subrequest {
				hostnames = ctx.hostnames
			}
		}
		log.Debug(idx, "<----- LOOP")
	}

	log.Debug(idx, "!!!!! LOOP COMPLETE !!!!!")
}

func (d *DnsSearch) validationLoop(idx uint, ctx *dnsSearchContext) {
	var badhost chan *DnsRequest = nil
	var in <-chan string = ctx.tovalidate
	var value string

	for {
		log.Debug(idx, "<----- VALIDATION LOOP")

		select {
		case value = <-in:
			log.Debug(idx, "[<] Validate: ", value, " - begin")
			value = "031337." + value
			badhost = ctx.badhost
			in = nil

		case badhost <- HostnameRequest(value):
			log.Debug(idx, "[<] Validate: ", value, " - complete")
			badhost = nil
			in = ctx.tovalidate

		case r := <-ctx.validated:
			parts := strings.SplitN(r.Host, ".", 2)
			domain := parts[1]
			if r == nil || r.Info == nil || !r.Info.Empty() {
				log.Error(idx, "< [V] Bad domain: ", domain)
			} else {
				log.Debug(idx, "< [V] Good domain: ", domain, " - run")

				ctx.generator.Run(domain)
				log.Debug(idx, "< [V] Good domain: ", domain, " - complete")
			}

			if atomic.AddInt32(&ctx.pending, -1) == 0 {
				log.Warning(idx, "! [V] Pending 0")
			}
		}
		log.Debug(idx, "<----- VALIDATION LOOP")
	}

	log.Debug(idx, "!!!!! LOOP COMPLETE !!!!!")
}

func (d *DnsSearch) Search() <-chan string {
	if len(d.domains) == 0 {
		return nil
	}

	generator := NewHostnameGenerator(d.wordlist)
	toresolve := make(chan *DnsRequest)
	badhost := make(chan *DnsRequest)
	validator := d.resolver.ResolveStream(badhost)
	resolver := d.resolver.ResolveStream(toresolve)

	context := &dnsSearchContext{
		out:       make(chan string),
		generator: generator,
		hostnames: generator.Iterator(),

		tovalidate: make(chan string),
		toresolve:  toresolve,
		badhost:    badhost,

		resolved:  resolver,
		validated: validator,

		pending: int32(0),
	}

	go func() {
		for _, domain := range d.domains {
			log.Debug("> [V] Validate: ", domain)
			atomic.AddInt32(&context.pending, 1)
			context.tovalidate <- domain
		}
	}()

	for i := uint(0); i < d.threads; i++ {
		go d.enumerationLoop(i, context)
		go d.validationLoop(i, context)
	}

	return context.out
}

func (d *DnsSearch) SaveWordlist() error {
	out, err := os.OpenFile(d.wordlist_path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	defer out.Close()

	for _, word := range d.wordlist.storage {
		fmt.Fprintf(out, "%s\n", word)
	}

	return nil
}
