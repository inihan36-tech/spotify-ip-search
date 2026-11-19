package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	version          = "1.1.3"
	minApplyDomains  = 9
	minQuickDomains  = 10
	latestReleaseAPI = "https://api.github.com/repos/inihan36-tech/spotify-ip-search/releases/latest"
	latestReleaseURL = "https://github.com/inihan36-tech/spotify-ip-search/releases/latest"
)

type configuration struct {
	Targets     map[string]string
	TargetOrder []string
	Core        []string
	PriorityIPs []string
	Published   []string
	ReserveDNS  map[string][]string
	SmartDNS    []string
	DoH         map[string][2]string
	PriorityDoH map[string][2]string
	WireDoH     map[string][2]string
	HostLists   map[string]string
	Discussions map[string]string
}

//go:embed sources.json
var configurationJSON []byte

//go:embed third-party-notices.txt
var thirdPartyNotices string

var config = decodeConfig(configurationJSON)
var targetDomains = config.TargetOrder

func decodeConfig(encoded []byte) configuration {
	var cfg configuration
	if err := json.Unmarshal(encoded, &cfg); err != nil {
		panic(err)
	}
	return cfg
}

var versionPattern = regexp.MustCompile(`^v?([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})$`)

func compareVersion(next, current string) bool {
	left, right := versionPattern.FindStringSubmatch(next), versionPattern.FindStringSubmatch(current)
	if left == nil || right == nil {
		return false
	}
	for index := 1; index <= 3; index++ {
		a, _ := strconv.Atoi(left[index])
		b, _ := strconv.Atoi(right[index])
		if a != b {
			return a > b
		}
	}
	return false
}

func checkForUpdate() {
	res, err := request(latestReleaseAPI, "", 0, 3*time.Second, 256_000, "application/vnd.github+json")
	if err != nil || res.status != 200 {
		return
	}
	var reply struct {
		Tag string `json:"tag_name"`
	}
	if json.Unmarshal(res.body, &reply) == nil && compareVersion(reply.Tag, version) {
		fmt.Printf("\nДоступно обновление v%s · %s\n", strings.TrimPrefix(reply.Tag, "v"), latestReleaseURL)
	}
}

func (options searchOptions) chooseRoute() (uint32, error) {
	control := pair{"1.1.1.1", "open.spotify.com"}
	// If a control IP serves Spotify, the tunnel ignored the requested destination.
	redirected := probe(control, 0, 2*time.Second, false).ok
	interfaces, err := directInterfaces()
	if !redirected && (err != nil || len(interfaces) == 0 || slices.Contains(interfaces, defaultInterface())) {
		return 0, nil
	}
	if options.verbose {
		fmt.Println("Проверяю прямое подключение через сетевой адаптер…")
	}
	if err != nil {
		return 0, err
	}
	for _, index := range interfaces {
		if !probe(control, index, 2*time.Second, false).ok {
			fmt.Println("Маршрут   · прямое подключение")
			return index, nil
		}
	}
	if !redirected {
		return 0, nil
	}
	return 0, errors.New("не удалось подтвердить маршрут проверки. Отключите режим TUN и повторите запуск")
}

func (options searchOptions) find(dnsOnly bool) results {
	type discovery struct {
		addresses   []string
		unavailable int
	}
	var hosts, discussions chan discovery
	if !dnsOnly {
		hosts, discussions = make(chan discovery, 1), make(chan discovery, 1)
		fetch := func(output chan<- discovery, sources map[string]string, parse func(string) []string) {
			addresses, unavailable := options.onlineCandidates(sources, parse)
			output <- discovery{addresses, unavailable}
		}
		go fetch(hosts, config.HostLists, listedHostsIPs)
		go fetch(discussions, config.Discussions, discussionIPs)
	}
	checked := results{}
	fmt.Println("Поиск     · SmartDNS…")
	priority := options.dnsCandidates(true)
	if !dnsOnly {
		for ip, domains := range options.publishedCandidates(config.PriorityIPs) {
			priority[ip] = domains
		}
	}
	fmt.Printf("Проверка  · приоритетных адресов: %d\n", len(priority))
	options.scan(priority, checked)
	if options.confirm(checked) {
		return checked
	}

	fmt.Println("Поиск     · DNS…")
	found := options.dnsCandidates(false)
	fmt.Printf("Проверка  · адресов из DNS: %d\n", len(found))
	options.scan(found, checked)
	if options.confirm(checked) || dnsOnly {
		return checked
	}

	reserve := options.publishedCandidates(config.Published)
	for domain, addresses := range config.ReserveDNS {
		for _, address := range addresses {
			if ip := publicIP(address); ip != "" && !options.excluded[ip] {
				if reserve[ip] == nil {
					reserve[ip] = map[string]bool{}
				}
				reserve[ip][domain] = true
			}
		}
	}
	fmt.Printf("Проверка  · резервный список: %d IP\n", len(reserve))
	options.scan(reserve, checked)
	if options.confirm(checked) {
		return checked
	}

	fmt.Println("Проверка  · адреса из открытых списков…")
	hostList, threads := <-hosts, <-discussions
	options.scan(options.publishedCandidates(append(hostList.addresses, threads.addresses...)), checked)
	options.confirm(checked)
	unavailable := hostList.unavailable + threads.unavailable
	if unavailable > 0 {
		fmt.Printf("Источники · недоступно: %d\n", unavailable)
	}
	return checked
}

func report(checked results, apply, verbose bool) int {
	best := bestIP(checked)
	checkedIPs := map[string]bool{}
	for candidate := range checked {
		checkedIPs[candidate.ip] = true
	}
	fmt.Printf("\nРезультат · проверено IP: %d\n", len(checkedIPs))
	coverage := len(best.domains)
	if coverage == 0 {
		fmt.Println("Подходящий IP не найден.")
		return 1
	}
	fmt.Printf("Лучший IP · %s · %d/%d доменов\n", best.ip, coverage, len(targetDomains))
	var missing []string
	for _, domain := range []string{"open.spotify.com", "accounts.spotify.com"} {
		if !slices.Contains(best.domains, domain) {
			missing = append(missing, domain)
		}
	}
	if len(missing) > 0 {
		fmt.Println("Доступ не подтверждён: " + strings.Join(missing, ", "))
	}
	if verbose {
		var omitted []string
		for _, domain := range targetDomains {
			if !slices.Contains(best.domains, domain) {
				omitted = append(omitted, domain)
			}
		}
		if len(omitted) > 0 {
			fmt.Println("Все домены без подтверждения: " + strings.Join(omitted, ", "))
		}
		fmt.Println("Проверен HTTPS. Вход в аккаунт и воспроизведение не проверялись.")
	}
	if apply && coverage >= minApplyDomains {
		return applyResult(best, verbose)
	}
	if apply {
		fmt.Printf("hosts     · запись пропущена, нужны хотя бы %d/%d доменов\n", minApplyDomains, len(targetDomains))
	}
	fmt.Print("\nСтроки для hosts\n\n")
	for _, domain := range best.domains {
		fmt.Printf("%s %s\n", best.ip, domain)
	}
	if coverage < len(targetDomains) {
		return 1
	}
	return 0
}

func run(args []string) int {
	flags := flag.NewFlagSet("SpotifyIpSearch.exe", flag.ContinueOnError)
	apply := flags.Bool("apply", false, "обновить hosts, веб-кэш Spotify и DNS")
	preview := flags.Bool("preview", false, "показать результат без записи в hosts")
	dnsOnly := flags.Bool("dns-only", false, "пропустить списки адресов и обсуждения")
	selected := flags.String("check-ip", "", "проверить один IPv4 на всех доменах Spotify")
	verbose := flags.Bool("verbose", false, "показать результат каждого запроса")
	seconds := flags.Int("timeout", 5, "тайм-аут HTTPS в секундах (2–15)")
	showVersion := flags.Bool("version", false, "показать версию")
	showLicenses := flags.Bool("licenses", false, "показать лицензии включённых компонентов")
	excluded := map[string]bool{}
	flags.Func("exclude", "пропустить IPv4 (можно указать несколько раз)", func(value string) error {
		ip := publicIP(value)
		if ip == "" {
			return errors.New("ожидается публичный IPv4")
		}
		excluded[ip] = true
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}
	if *showLicenses {
		fmt.Print(thirdPartyNotices)
		return 0
	}
	if flags.NArg() != 0 || *seconds < 2 || *seconds > 15 || (*apply && *preview) {
		fmt.Fprintln(os.Stderr, "Некорректные параметры. Используйте --help.")
		return 2
	}
	ip := publicIP(*selected)
	if *selected != "" && (ip == "" || excluded[ip]) {
		fmt.Fprintln(os.Stderr, "--check-ip ожидает публичный IPv4, которого нет в --exclude")
		return 2
	}
	shouldApply := !*preview && (*apply || len(args) == 0)
	mode := "проверка"
	if shouldApply {
		mode = "поиск и обновление hosts"
	}
	fmt.Printf("Spotify IP Search v%s · %s\n\n", version, mode)
	defer checkForUpdate()
	options := searchOptions{timeout: time.Duration(*seconds) * time.Second, verbose: *verbose, excluded: excluded}
	source, err := options.chooseRoute()
	if err != nil {
		fmt.Printf("Маршрут   · %v\n", err)
		return 2
	}
	options.interfaceIndex = source
	var checked results
	if ip != "" {
		fmt.Printf("Проверка  · %s на %d доменах…\n", ip, len(targetDomains))
		checked = results{}
		for _, check := range options.check(allPairs(ip), true) {
			checked[check.pair] = check
		}
		options.confirm(checked)
	} else {
		checked = options.find(*dnsOnly)
	}
	return report(checked, shouldApply, *verbose)
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--write-hosts" {
		os.Exit(writeHostsChild(args[1:]))
	}
	code := run(args)
	if len(args) == 0 {
		pauseAtExit()
	}
	os.Exit(code)
}
