package main

import (
	"context"
	"fmt"
	"html"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

const workers, maxSourceIPs = 10, 128

type candidates map[string]map[string]bool
type results map[pair]probeResult

func parallel[In, Out any](inputs []In, run func(In) Out) []Out {
	output := make([]Out, len(inputs))
	var group sync.WaitGroup
	slots := make(chan struct{}, workers)
	for index, input := range inputs {
		slots <- struct{}{}
		group.Add(1)
		go func() {
			defer group.Done()
			defer func() { <-slots }()
			output[index] = run(input)
		}()
	}
	group.Wait()
	return output
}

type searchOptions struct {
	sourceIP string
	timeout  time.Duration
	verbose  bool
	excluded map[string]bool
}

type dnsJob struct {
	domain, source string
	lookup         func(string) ([]string, error)
	limited        bool
}

func localLookup(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	records, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", domain)
	var addresses []string
	for _, record := range records {
		addresses = append(addresses, record.Unmap().String())
	}
	return addresses, err
}

func (options searchOptions) dnsCandidates() candidates {
	var jobs []dnsJob
	for _, domain := range append(slices.Clone(config.Core), "i.scdn.co") {
		jobs = append(jobs,
			dnsJob{domain, "Системный DNS", systemDNS, false},
			dnsJob{domain, "Локальное разрешение", localLookup, false},
			dnsJob{domain, "SmartDNS dns.malw.link", func(domain string) ([]string, error) { return smartDNS(domain, options.sourceIP) }, false})
		for name, endpoint := range config.DoH {
			jobs = append(jobs, dnsJob{domain, name, func(domain string) ([]string, error) {
				return queryDoH(domain, options.sourceIP, endpoint)
			}, true})
		}
	}
	type answer struct {
		addresses []string
		err       error
	}
	answers := parallel(jobs, func(job dnsJob) answer {
		addresses, err := job.lookup(job.domain)
		return answer{addresses, err}
	})
	found := candidates{}
	for index, reply := range answers {
		job := jobs[index]
		if options.verbose {
			fmt.Printf("  %s · %s: %s\n", job.source, job.domain, describeSource(reply.addresses, reply.err))
		}
		for _, address := range reply.addresses {
			ip := publicIP(address)
			if ip == "" || options.excluded[ip] {
				continue
			}
			if found[ip] == nil {
				found[ip] = map[string]bool{}
			}
			if job.limited {
				found[ip][job.domain] = true
			} else {
				for domain := range config.Targets {
					found[ip][domain] = true
				}
			}
		}
	}
	return found
}

func (options searchOptions) check(jobs []pair, retry bool) []probeResult {
	checks := parallel(jobs, func(candidate pair) probeResult {
		return probe(candidate, options.sourceIP, options.timeout, retry)
	})
	if options.verbose {
		for _, check := range checks {
			status := "FAIL"
			if check.ok {
				status = "OK"
			}
			fmt.Printf("  %-4s %-15s %-24s %s\n", status, check.ip, check.domain, check.reason)
		}
	}
	return checks
}

func (options searchOptions) scan(found candidates, checked results) {
	var coreJobs []pair
	for ip, domains := range found {
		for _, domain := range config.Core {
			candidate := pair{ip, domain}
			if _, exists := checked[candidate]; domains[domain] && !exists {
				coreJobs = append(coreJobs, candidate)
			}
		}
	}
	for _, check := range options.check(coreJobs, true) {
		checked[check.pair] = check
	}
	responsive := map[string]bool{}
	for candidate, check := range checked {
		if check.ok && slices.Contains(config.Core, candidate.domain) {
			responsive[candidate.ip] = true
		}
	}
	var remaining []pair
	for ip := range found {
		if !responsive[ip] {
			continue
		}
		for _, domain := range targetDomains {
			candidate := pair{ip, domain}
			if _, exists := checked[candidate]; !exists && !slices.Contains(config.Core, domain) {
				remaining = append(remaining, candidate)
			}
		}
	}
	for _, check := range options.check(remaining, true) {
		checked[check.pair] = check
	}
}

type winner struct {
	ip      string
	domains []string
	elapsed time.Duration
}

func bestIP(checked results) winner {
	passed := map[string]map[string]time.Duration{}
	for candidate, check := range checked {
		if !check.ok {
			continue
		}
		if passed[candidate.ip] == nil {
			passed[candidate.ip] = map[string]time.Duration{}
		}
		passed[candidate.ip][candidate.domain] = check.elapsed
	}
	var best winner
	for ip, domains := range passed {
		current := winner{ip: ip}
		for _, domain := range targetDomains {
			if elapsed, ok := domains[domain]; ok {
				current.domains = append(current.domains, domain)
				current.elapsed += elapsed
			}
		}
		if len(current.domains) > len(best.domains) || (len(current.domains) == len(best.domains) &&
			(current.elapsed < best.elapsed || (current.elapsed == best.elapsed && current.ip < best.ip))) {
			best = current
		}
	}
	return best
}

func (options searchOptions) confirm(checked results) bool {
	for {
		best := bestIP(checked)
		if len(best.domains) != len(targetDomains) {
			return false
		}
		fmt.Printf("Проверка  · повторно проверяю %s…\n", best.ip)
		jobs := allPairs(best.ip)
		passed := true
		for _, check := range options.check(jobs, false) {
			if !check.ok {
				checked[check.pair] = check
				passed = false
			}
		}
		if passed {
			return true
		}
	}
}

func allPairs(ip string) []pair {
	jobs := make([]pair, 0, len(targetDomains))
	for _, domain := range targetDomains {
		jobs = append(jobs, pair{ip, domain})
	}
	return jobs
}

func (options searchOptions) addPublished(addresses []string, checked results) {
	allDomains := map[string]bool{}
	for domain := range config.Targets {
		allDomains[domain] = true
	}
	found := candidates{}
	for _, address := range addresses {
		if ip := publicIP(address); ip != "" && !options.excluded[ip] {
			found[ip] = allDomains
		}
	}
	options.scan(found, checked)
}

func listedHostsIPs(page string) []string {
	counts := map[string]map[string]bool{}
	var order []string
	for line := range strings.Lines(page) {
		fields, _, _ := strings.Cut(line, "#")
		columns := strings.Fields(fields)
		if len(columns) < 2 {
			continue
		}
		ip := publicIP(columns[0])
		if ip == "" {
			continue
		}
		for _, alias := range columns[1:] {
			domain := strings.TrimRight(strings.ToLower(alias), ".")
			if _, known := config.Targets[domain]; !known {
				continue
			}
			if counts[ip] == nil {
				counts[ip] = map[string]bool{}
				order = append(order, ip)
			}
			counts[ip][domain] = true
		}
	}
	slices.SortStableFunc(order, func(a, b string) int { return len(counts[b]) - len(counts[a]) })
	return order[:min(len(order), maxSourceIPs)]
}

var (
	pageScripts = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>|<style\b[^>]*>.*?</style\s*>`)
	pageTags    = regexp.MustCompile(`<[^>]+>`)
	hostPair    = regexp.MustCompile(`(?i)(\b(?:\d{1,3}\.){3}\d{1,3})\s+(?:[a-z0-9-]+\.)*(?:spotify\.com|spotifycdn\.(?:com|net)|scdn\.co)\b`)
)

func discussionIPs(page string) []string {
	page = html.UnescapeString(pageTags.ReplaceAllString(pageScripts.ReplaceAllString(page, " "), " "))
	matches := hostPair.FindAllStringSubmatchIndex(page, -1)
	var found []string
	for index := len(matches) - 1; index >= 0 && len(found) < maxSourceIPs; index-- {
		m := matches[index]
		if (m[0] > 0 && page[m[0]-1] == '.') || (m[1] < len(page) && page[m[1]] == '.') {
			continue
		}
		if ip := publicIP(page[m[2]:m[3]]); ip != "" && !slices.Contains(found, ip) {
			found = append(found, ip)
		}
	}
	return found
}

func describeSource(addresses []string, err error) string {
	if err != nil {
		return err.Error()
	}
	if len(addresses) == 0 {
		return "нет IPv4"
	}
	return strings.Join(addresses, ", ")
}

func (options searchOptions) onlineCandidates(sources map[string]string, parse func(string) []string) ([]string, int) {
	type source struct{ name, link string }
	var jobs []source
	for name, link := range sources {
		jobs = append(jobs, source{name, link})
	}
	type answer struct {
		addresses []string
		err       error
	}
	answers := parallel(jobs, func(item source) answer {
		const timeout = 10 * time.Second
		res, err := request(item.link, "", "", timeout, 8_000_000, "")
		if isTimeout(err) {
			res, err = request(item.link, "", "", timeout, 8_000_000, "")
		}
		if err != nil {
			return answer{err: err}
		}
		if res.status != 200 {
			return answer{err: fmt.Errorf("HTTP %d", res.status)}
		}
		return answer{addresses: parse(string(res.body))}
	})
	var addresses []string
	unavailable := 0
	for index, reply := range answers {
		if options.verbose {
			fmt.Printf("  %s · %s\n", jobs[index].name, describeSource(reply.addresses, reply.err))
		}
		if reply.err != nil {
			unavailable++
		}
		addresses = append(addresses, reply.addresses...)
	}
	return addresses, unavailable
}
