//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	replaceFile    = kernel32.NewProc("ReplaceFileW")
	consoleWindow  = kernel32.NewProc("GetConsoleWindow")
	shellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")
	ole32          = windows.NewLazySystemDLL("ole32.dll")
)

func systemDNS(domain string) ([]string, error) {
	var records *windows.DNSRecord
	const noHostsFile = 0x40
	err := windows.DnsQuery(domain+".", 1, noHostsFile, nil, &records, nil)
	if err != nil {
		return nil, err
	}
	defer windows.DnsRecordListFree(records, 1) // DnsFreeRecordList
	var addresses []string
	for record := records; record != nil; record = record.Next {
		if record.Type == 1 && record.Length == 4 {
			address := [4]byte(record.Data[:4])
			addresses = append(addresses, netip.AddrFrom4(address).String())
		}
	}
	return addresses, nil
}

func directSourceIPs() ([]string, error) {
	const includeGateways = 0x80
	size := uint32(15_000)
	for range 3 {
		buffer := make([]byte, size)
		adapter := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, includeGateways, 0, adapter, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var addresses []string
		for current := adapter; current != nil; current = current.Next {
			if current.OperStatus != windows.IfOperStatusUp || current.FirstGatewayAddress == nil {
				continue
			}
			// Virtual VPN adapters may report the same interface type as Ethernet.
			const hardwareInterface = 0x01
			row := windows.MibIfRow2{InterfaceIndex: current.IfIndex}
			if windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row) != nil ||
				row.InterfaceAndOperStatusFlags&hardwareInterface == 0 {
				continue
			}
			for address := current.FirstUnicastAddress; address != nil; address = address.Next {
				if ip := address.Address.IP().To4(); ip != nil && !ip.IsLinkLocalUnicast() {
					addresses = append(addresses, ip.String())
				}
			}
		}
		runtime.KeepAlive(buffer)
		return addresses, nil
	}
	return nil, errors.New("список адаптеров изменился")
}

func pauseAtExit() {
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) != nil ||
		windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) != nil {
		return
	}
	fmt.Print("\nНажмите Enter, чтобы закрыть окно…")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func updateHostsContents(original []byte, ip string, domains []string) ([]byte, error) {
	if bytes.ContainsRune(original, '\x00') {
		return nil, errors.New("файл hosts содержит нулевые байты")
	}
	content := string(original)
	var updated strings.Builder
	if remainder, hasBOM := strings.CutPrefix(content, "\xef\xbb\xbf"); hasBOM {
		updated.WriteString("\xef\xbb\xbf")
		content = remainder
	}
	newline := "\n"
	if strings.Contains(content, "\r\n") || !strings.Contains(content, "\n") {
		newline = "\r\n"
	}
	for line := range strings.Lines(content) {
		body := strings.TrimRight(line, "\r\n")
		fields, comment, hasComment := strings.Cut(body, "#")
		columns := strings.Fields(fields)
		if len(columns) < 2 {
			updated.WriteString(line)
			continue
		}
		kept := []string{columns[0]}
		for _, alias := range columns[1:] {
			if !slices.Contains(domains, strings.TrimRight(strings.ToLower(alias), ".")) {
				kept = append(kept, alias)
			}
		}
		if len(kept) == len(columns) {
			updated.WriteString(line)
			continue
		}
		if len(kept) > 1 {
			updated.WriteString(strings.Join(kept, " "))
			if hasComment {
				updated.WriteByte(' ')
			}
		}
		if hasComment {
			updated.WriteString("#" + comment)
		}
		if len(kept) > 1 || hasComment {
			updated.WriteString(newline)
		}
	}
	if strings.TrimPrefix(updated.String(), "\xef\xbb\xbf") != "" && !strings.HasSuffix(updated.String(), "\n") {
		updated.WriteString(newline)
	}
	for _, domain := range domains {
		fmt.Fprintf(&updated, "%s %s%s", ip, domain, newline)
	}
	return []byte(updated.String()), nil
}

func writeHosts(path, ip string, domains []string) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated, err := updateHostsContents(original, ip, domains)
	if err != nil || bytes.Equal(original, updated) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "hosts.*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(updated)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, original) {
		return errors.New("файл hosts изменился во время записи, повторите запуск")
	}
	destination, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(file.Name())
	if err != nil {
		return err
	}
	ok, _, err := replaceFile.Call(uintptr(unsafe.Pointer(destination)), uintptr(unsafe.Pointer(source)), 0, 0, 0, 0)
	if ok == 0 {
		return err
	}
	return nil
}

func cleanCacheDirectory(path string) (bool, error) {
	if !filepath.IsAbs(path) {
		return false, errors.New("путь к кэшу должен быть абсолютным")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, errors.New("путь к кэшу не является обычной папкой")
	}
	verified, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(filepath.Clean(verified), filepath.Clean(path)) {
		return false, errors.New("папка кэша перенаправлена")
	}
	if err := os.RemoveAll(path); err != nil {
		return false, err
	}
	return true, nil
}

func webCache(local, roaming string) (int, error) {
	var roots []string
	if filepath.IsAbs(local) {
		roots = append(roots, filepath.Join(local, "Spotify"))
		packages, _ := filepath.Glob(filepath.Join(local, "Packages", "SpotifyAB.SpotifyMusic_*"))
		for _, path := range packages {
			roots = append(roots, filepath.Join(path, "LocalCache", "Spotify"))
		}
	}
	if filepath.IsAbs(roaming) {
		roots = append(roots, filepath.Join(roaming, "Spotify"))
	}
	var cleared int
	var failures []error
	for _, root := range roots {
		browser := filepath.Join(root, "Browser")
		profiles := []string{browser, filepath.Join(browser, "Default"), filepath.Join(root, "Default"), filepath.Join(root, "User Data", "Default")}
		additional, _ := filepath.Glob(filepath.Join(browser, "Profile *"))
		for _, profile := range append(profiles, additional...) {
			for _, name := range []string{"Cache", "Code Cache", "GPUCache"} {
				path := filepath.Join(profile, name)
				removed, err := cleanCacheDirectory(path)
				if err != nil {
					failures = append(failures, fmt.Errorf("%s: %w", path, err))
				}
				if removed {
					cleared++
				}
			}
		}
	}
	return cleared, errors.Join(failures...)
}

const dnsFlushFailed = 3

func writeSystemHosts(ip string, domains []string) (int, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return 2, err
	}
	if err := writeHosts(filepath.Join(system, "drivers", "etc", "hosts"), ip, domains); err != nil {
		return 2, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(system, "ipconfig.exe"), "/flushdns")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := cmd.Run(); err != nil {
		return dnsFlushFailed, err
	}
	return 0, nil
}

type shellExecInfo struct {
	size, mask                     uint32
	window                         windows.Handle
	verb, file, parameters, folder *uint16
	show                           int32
	instance                       windows.Handle
	itemList                       uintptr
	class                          *uint16
	classKey                       windows.Handle
	hotkey                         uint32
	icon, process                  windows.Handle
}

func elevatedWrite(ip string, domains []string) (int, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return writeSystemHosts(ip, domains)
	}
	exe, err := os.Executable()
	if err != nil {
		return 2, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 2, err
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{"--write-hosts", ip, strings.Join(domains, ",")}))
	if err != nil {
		return 2, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	status, _, _ := ole32.NewProc("CoInitializeEx").Call(0, 0x6) // STA, OLE1 DDE disabled.
	if int32(status) >= 0 {
		defer ole32.NewProc("CoUninitialize").Call()
	}
	window, _, _ := consoleWindow.Call()
	info := shellExecInfo{mask: 0x40 | 0x100, window: windows.Handle(window), verb: windows.StringToUTF16Ptr("runas"), file: file, parameters: params}
	info.size = uint32(unsafe.Sizeof(info))
	ok, _, err := shellExecuteEx.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return 2, err
	}
	if info.process == 0 {
		return 2, errors.New("Windows не вернула процесс записи hosts")
	}
	defer windows.CloseHandle(info.process)
	if _, err := windows.WaitForSingleObject(info.process, windows.INFINITE); err != nil {
		return 2, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return 2, err
	}
	if code != 0 && code != dnsFlushFailed {
		return 2, fmt.Errorf("Windows не смогла обновить hosts (код %d)", code)
	}
	return int(code), nil
}

func writeHostsChild(args []string) int {
	if len(args) != 2 || !windows.GetCurrentProcessToken().IsElevated() {
		return 2
	}
	ip, domains := publicIP(args[0]), strings.Split(args[1], ",")
	if ip == "" || len(domains) < minApplyDomains || len(domains) > len(targetDomains) {
		return 2
	}
	seen := map[string]bool{}
	for _, domain := range domains {
		if _, known := config.Targets[domain]; !known || seen[domain] {
			return 2
		}
		seen[domain] = true
	}
	code, err := writeSystemHosts(ip, domains)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return code
}

func applyResult(best winner, verbose bool) int {
	fmt.Println("\nhosts     · обновляю записи…")
	code, err := elevatedWrite(best.ip, best.domains)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		fmt.Println("hosts     · запись отменена")
		return 2
	}
	if code != 0 && code != dnsFlushFailed {
		fmt.Printf("hosts     · ошибка записи: %v\n", err)
		return 2
	}
	fmt.Printf("hosts     · записано доменов: %d\n", len(best.domains))
	cleared, cacheErr := webCache(os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA"))
	fmt.Printf("Веб-кэш   · очищено папок: %d\n", cleared)
	if cacheErr != nil {
		if verbose {
			fmt.Println(cacheErr)
		}
		fmt.Println("Веб-кэш   · очистка неполная. Закройте Spotify и повторите запуск.")
	}
	if code == dnsFlushFailed {
		fmt.Println("DNS       · ошибка сброса кэша")
	} else {
		fmt.Println("DNS       · кэш сброшен")
	}
	fmt.Println("\nПерезапустите Spotify, если он открыт.")
	if cacheErr != nil || code != 0 {
		return 2
	}
	return 0
}
