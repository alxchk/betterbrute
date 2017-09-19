package main

import (
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	AllDnsRecords []uint16 = []uint16{
		dns.TypeANY, dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS,
		dns.TypeSPF, dns.TypeTXT, dns.TypeSRV, dns.TypeSOA,
	}
	ReferenceNS string = "8.8.8.8"
	ZeroIp net.IP = net.ParseIP("0.0.0.0")
)

type (
	DnsInfo struct {
		Ns     []string
		Mx     []string
		Srv    []string
		Spf    []string
		Txt    []string
		Cname  []string
		Ip     []net.IP
		Serial uint32
		Mail   string
		SoaNs  string
		Axfr   bool
	}

	DnsResponse struct {
		Error error
		Host  string
		Rcode int
		BadNS bool
		Info  *DnsInfo
	}

	DnsRequest struct {
		hostname   string
		nameserver string
		types      []uint16
	}

	ResolverStream struct {
		group    *sync.WaitGroup
		request  <-chan *DnsRequest
		response chan *DnsResponse
		chooser  *Chooser
	}

	Chooser struct {
		aliveNs []string

		iter  chan string
		alive chan string
		dead  chan string
		bad   chan string
	}

	Validator struct {
		next  chan string
		check chan string
		bad   chan string

		alive chan string
		dead  chan string
	}

	Resolver struct {
		validator *Validator
		chooser   *Chooser
		threads   uint
	}

	Checker struct {
		validator *Validator
		threads   uint
	}
)

func (r *DnsResponse) String() string {
	out := r.Host + "\t"
	if r.Error != nil {
		out = out + "ERROR: " + r.Error.Error()
	} else {
		out = out + r.Info.String()
	}

	return out
}

func (i *DnsInfo) Empty() bool {
	return len(i.Ip) == 0 && len(i.Cname) == 0 && len(i.Mx) == 0 &&
		len(i.Ns) == 0 && len(i.Srv) == 0 && len(i.Txt) == 0 && len(i.Spf) == 0 &&
		i.Serial == 0 && i.Axfr == false
}

func (i *DnsInfo) String() string {
	var out []string
	if len(i.Ip) > 0 {
		ipstr := []string{}
		for _, ip := range i.Ip {
			ipstr = append(ipstr, ip.String())
		}
		out = append(out, "IP:"+strings.Join(ipstr, ","))
	}

	if len(i.Cname) > 0 {
		out = append(out, "CNAME: "+strings.Join(i.Cname, ","))
	}

	if len(i.Mx) > 0 {
		out = append(out, "MX: "+strings.Join(i.Mx, ","))
	}

	if len(i.Ns) > 0 {
		out = append(out, "NS: "+strings.Join(i.Ns, ","))
	}

	if len(i.Srv) > 0 {
		out = append(out, "SRV: "+strings.Join(i.Srv, ","))
	}

	if len(i.Txt) > 0 {
		out = append(out, "TXT: "+strings.Join(i.Txt, ","))
	}

	if len(i.Spf) > 0 {
		out = append(out, "SPF: "+strings.Join(i.Spf, ","))
	}

	if i.Serial > 0 {
		out = append(out, "Serial: "+strconv.Itoa(int(i.Serial)))
	}

	if i.Mail != "" {
		out = append(out, "Mail: "+i.Mail)
	}

	if i.SoaNs != "" {
		out = append(out, "SOANS: "+i.SoaNs)
	}

	if i.Axfr {
		out = append(out, "AXFR")
	}

	return strings.Join(out, "|")
}

var (
	ValidateDnsHostname = "ifconfig.co"
	ValidateDnsIp       = net.ParseIP("188.113.88.193")
	ValidateTimeout     = 3 * time.Second
	ValidateStressTest  = 2
)

func nextNs(list []string, current uint) (bool, string, uint) {
	l := uint(len(list))
	if l == 0 {
		return false, "", 0
	}

	if current >= l {
		current = 0
	}

	return true, list[current], current + 1
}

func NewChooser(validator *Validator) *Chooser {
	chooser := &Chooser{
		iter:  validator.next,
		alive: validator.alive,
		dead:  validator.dead,
		bad:   validator.bad,
	}

	go chooser.loop()

	return chooser
}

func (c *Chooser) GetNs() string {
	return <-c.iter
}

func (c *Chooser) loop() {
	var (
		success bool
		nextns  string
		current uint
		next    chan<- string = nil
	)

	for {
		select {
		case remove := <-c.bad:
			for i, v := range c.aliveNs {
				if v == remove {
					c.aliveNs = append(c.aliveNs[:i], c.aliveNs[i+1:]...)
					break
				}
			}

			success, nextns, current = nextNs(c.aliveNs, current)
			if !success {
				next = nil
			}

		case aliveNs := <-c.alive:
			c.aliveNs = append(c.aliveNs, aliveNs)
			if next == nil {
				_, nextns, current = nextNs(c.aliveNs, current)
				next = c.iter
			}

		case _ = <-c.dead:

		case next <- nextns:
			_, nextns, current = nextNs(c.aliveNs, current)
		}
	}
}

func NewValidator(threads uint) *Validator {
	v := &Validator{
		next:  make(chan string),
		check: make(chan string),
		bad:   make(chan string),
		dead:  make(chan string),
		alive: make(chan string),
	}

	for i := uint(0); i < threads; i++ {
		go v.loop()
	}

	return v
}

func checkFakeResolves(ns string) bool {
	criteria := []string{
		"0xffffffff." + ValidateDnsHostname,
		"djigurda-lol." + ValidateDnsHostname,
		"www." + ValidateDnsHostname,
		"some.nonexisting.comain" + ValidateDnsHostname,
		"ftp.google.com",
		"ftp.hotmail.com",
		"test.samsung.com",
		"test.www.google.com",
		"test.hotmail.com",
		"xyz.pages.samsung.com",
	}

	for i := 0; i < ValidateStressTest; i++ {
		for _, record := range criteria {
			r := resolve(record, ns, []uint16{dns.TypeA}, false)
			if r.Info != nil && r.Info.Ip != nil && len(r.Info.Ip) > 0 {
				return false
			}

			r = resolve(record, ns, []uint16{dns.TypeANY}, false)
			if r.Info != nil && r.Info.Ip != nil && len(r.Info.Ip) > 0 {
				return false
			}
		}
	}

	return true
}

func (v *Validator) loop() {
	for ns := range v.check {
		r := resolve(ValidateDnsHostname, ns, []uint16{dns.TypeANY}, false)

		switch {
		case r.Error != nil:
			v.dead <- ns

		case len(r.Info.Ip) == 0 || !r.Info.Ip[0].Equal(ValidateDnsIp):
			r := resolve(ValidateDnsHostname, ns, []uint16{dns.TypeA}, false)
			if r.Error != nil || r.Info == nil || len(r.Info.Ip) == 0 || !r.Info.Ip[0].Equal(ValidateDnsIp) {
				v.dead <- ns
			} else {
				if checkFakeResolves(ns) {
					v.alive <- ns
				} else {
					v.dead <- ns
				}
			}

		default:
			if checkFakeResolves(ns) {
				v.alive <- ns
			} else {
				v.dead <- ns
			}
		}
	}
}
func (v *Validator) AddNs(Ns ...string) {
	for _, ns := range Ns {
		v.check <- ns
	}
}

func (v *Validator) BadNs(Ns ...string) {
	for _, ns := range Ns {
		v.bad <- ns
	}
}

func resolve(host, ns string, ftype []uint16, reference bool) *DnsResponse {

	if !strings.Contains(ns, ":") {
		ns = ns + ":53"
	}

	c := new(dns.Client)
	c.DialTimeout = ValidateTimeout
	c.ReadTimeout = ValidateTimeout
	c.SingleInflight = true

	var info DnsInfo

mainloop:
	for _, dnstype := range ftype {
		m := new(dns.Msg)
		m.Id = dns.Id()

		if dnstype == dns.TypeAXFR {
			t := new(dns.Transfer)
			m.SetAxfr(dns.Fqdn(host))
			axfr, err := t.In(m, ns)
			log.Debug("AXFR ", host, "@", ns, " Error: ", err)

			out := &DnsResponse{
				Host:  host,
				Error: err,
			}

			if err == nil {
				axfrok := false
				for c := range axfr {
					if c.Error == nil && len(c.RR) > 0 {
						axfrok = true
						break
					}
				}

				out.Info = &DnsInfo{
					Axfr: axfrok,
				}
			}

			return out
		}

		m.SetQuestion(dns.Fqdn(host), dnstype)

		in, _, err := c.Exchange(m, ns)
		if in != nil && in.MsgHdr.Truncated {
			c.Net = "tcp"
			continue mainloop
		}

		if err != nil {
			return &DnsResponse{
				Host:  host,
				Error: err,
			}
		}

		switch {
		case in.MsgHdr.Rcode == dns.RcodeNameError:
			break mainloop

		case in.MsgHdr.Rcode != dns.RcodeSuccess:
			log.Debug("DNSRESOLVE: ", host, "@NS", ns, ", Type: ", ftype, ": ", dns.RcodeToString[in.MsgHdr.Rcode])
			continue mainloop
		}

		if reference {
		    return resolve(host, ReferenceNS, ftype, false);
		}

		for _, a := range in.Answer {
			rrtype := a.Header().Rrtype
			switch {
			case rrtype == dns.TypeA:
				if ZeroIp.Equal(a.(*dns.A).A) {
					return &DnsResponse{
						Rcode: dns.RcodeSuccess,
						Error: nil,
						Host:  host,
						Info:  &info,
						BadNS: true,
					}
				}

				info.Ip = append(info.Ip, a.(*dns.A).A)
			case rrtype == dns.TypeAAAA:
				info.Ip = append(info.Ip, a.(*dns.AAAA).AAAA)
			case rrtype == dns.TypeCNAME:
				info.Cname = append(info.Cname, a.(*dns.CNAME).Target)
			case rrtype == dns.TypeMX:
				info.Mx = append(info.Mx, a.(*dns.MX).Mx)
			case rrtype == dns.TypeNS:
				info.Ns = append(info.Ns, a.(*dns.NS).Ns)
			case rrtype == dns.TypeSPF:
				info.Spf = append(info.Spf, a.(*dns.SPF).Txt...)
			case rrtype == dns.TypeTXT:
				info.Txt = append(info.Txt, a.(*dns.TXT).Txt...)
			case rrtype == dns.TypeSRV:
				info.Srv = append(info.Spf, a.(*dns.SRV).Target)
			case rrtype == dns.TypeSOA:
				info.Serial = a.(*dns.SOA).Serial
				info.Mail = a.(*dns.SOA).Mbox
				info.SoaNs = a.(*dns.SOA).Ns
			}
		}

		if dnstype == dns.TypeANY && !info.Empty() {
			break mainloop
		}
	}

	return &DnsResponse{
		Rcode: dns.RcodeSuccess,
		Error: nil,
		Host:  host,
		Info:  &info,
	}
}

func NewResolver(threads uint) *Resolver {
	validator := NewValidator(threads)

	r := &Resolver{
		threads:   threads,
		validator: validator,
		chooser:   NewChooser(validator),
	}

	return r
}

func (r *Resolver) One(hostname string, types []uint16) *DnsResponse {
	ns := r.chooser.GetNs()
	return resolve(hostname, ns, types, true)
}

func NewResolverStream(chooser *Chooser, threads uint, hosts <-chan *DnsRequest) *ResolverStream {
	stream := &ResolverStream{
		group:    new(sync.WaitGroup),
		request:  hosts,
		response: make(chan *DnsResponse),
		chooser:  chooser,
	}

	for i := uint(0); i < threads; i++ {
		stream.group.Add(1)
		go stream.loop()
	}

	go func() {
		stream.group.Wait()
		log.Debug(" ------------------ RESOLVER STREAM EXITS -------------------")
		close(stream.response)
	}()

	return stream
}

func (s *ResolverStream) loop() {
	for request := range s.request {
		var (
			response   *DnsResponse
			hostname   string
			nameserver string
			types      []uint16
			explicit   bool = false
		)

		hostname = request.hostname
		if request.nameserver != "" {
			nameserver = request.nameserver
			explicit = true
		} else {
			nameserver = s.chooser.GetNs()
		}

		if len(request.types) != 0 {
			types = request.types
		} else {
			types = AllDnsRecords
		}

		log.Debug("<<-- Send request: ", hostname, " NS: ", nameserver, " TYPES: ", types)

		for retry := 0; retry < 3; retry++ {
			response = resolve(hostname, nameserver, types, true)
			if response.Error != nil {
				if response.BadNS {
					log.Error("Bad NS: " + nameserver)
					nameserver = s.chooser.GetNs()
					s.chooser.bad <- nameserver
					continue
				}

				_, ok := response.Error.(*net.OpError)
				if ok && !explicit {
					nameserver = s.chooser.GetNs()
					continue
				} else {
					log.Debug("Error: ", hostname, " Rcode: ", dns.RcodeToString[response.Rcode])
					break
				}
			}

			break
		}

		log.Debug("--> Got response: Host: ", hostname, ", Reponse: ", response)
		s.response <- response
		log.Debug("<-- Flush response: Host: ", hostname, ", Response: ", response)
	}

	log.Debug("RESOLVER WRITER COMPLETE. CLOSE CHANNEL")
	s.group.Done()

}

func (r *ResolverStream) Iterator() <-chan *DnsResponse {
	return r.response
}

func (r *Resolver) ResolveStream(hosts <-chan *DnsRequest) <-chan *DnsResponse {
	return NewResolverStream(r.chooser, r.threads, hosts).Iterator()
}

func HostnameRequest(hostname string) *DnsRequest {
	return &DnsRequest{
		hostname: hostname,
	}
}

func AxfrRequest(zone, ns string) *DnsRequest {
	return &DnsRequest{
		hostname:   zone,
		nameserver: ns + ":53",
		types: []uint16{
			dns.TypeAXFR,
		},
	}
}

func (r *Resolver) AddNs(ns ...string) {
	go func() {
		for _, n := range ns {
			r.validator.AddNs(n)
		}
	}()
}

func (r *Resolver) AddNsFromList(list string) error {
	lfile, err := os.Open(list)
	if err != nil {
		return err
	}

	go func() {
		reader := bufio.NewScanner(lfile)
		for reader.Scan() {
			r.validator.AddNs(reader.Text())
		}

		lfile.Close()
	}()

	return nil
}

func NewChecker(threads uint) *Checker {
	return &Checker{
		validator: NewValidator(threads),
		threads:   threads,
	}
}

func (c *Checker) FilterAliveFromStream(in io.Reader, out io.Writer) {
	reader := bufio.NewScanner(in)
	sync := make(chan uint, c.threads)

	go func() {
		cnt := uint(0)
		for reader.Scan() {
			c.validator.check <- reader.Text()
			cnt++
			sync <- cnt
		}
		close(sync)
	}()

	for range sync {
		select {
		case _ = <-c.validator.dead:
		case alive := <-c.validator.alive:
			out.Write([]byte(alive + "\n"))
		}
	}
}
