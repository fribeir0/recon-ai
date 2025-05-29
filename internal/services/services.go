package services

import (
    "bufio"
    "bytes"
    "context"
    "fmt"
    "log"
    "net"
    "os/exec"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"

    "go-recon-amass-nmap/internal/models"
)

var nmapRegex = regexp.MustCompile(`(?m)^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$`)

func expandCIDR(cidr string) ([]string, error) {
    ip, ipnet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
    }
    var ips []string
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    if len(ips) > 2 {
        return ips[1 : len(ips)-1], nil
    }
    return ips, nil
}

func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] != 0 {
            break
        }
    }
}

// RunSubfinder calls the subfinder binary on the PATH
func RunSubfinder(domain string) ([]string, error) {
    cmd := exec.Command("subfinder", "-d", domain, "-silent")
    out, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

// RunAmassIntel fetches hosts via amass intel
func RunAmassIntel(target string) ([]string, error) {
    var args []string
    if net.ParseIP(target) != nil || strings.Contains(target, "/") {
        args = []string{"intel", "-ip", target, "-silent"}
    } else {
        args = []string{"enum", "-d", target, "-silent"}
    }
    cmd := exec.Command("amass", args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    if err := cmd.Run(); err != nil {
        return nil, err
    }
    var hosts []string
    scanner := bufio.NewScanner(&out)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" {
            hosts = append(hosts, line)
        }
    }
    return hosts, nil
}

// ScanNmap runs nmap -sV grouped by host concurrently
func ScanNmap(hosts []string) []models.PortService {
    var wg sync.WaitGroup
    ch := make(chan models.PortService)
    for _, h := range hosts {
        wg.Add(1)
        go func(host string) {
            defer wg.Done()
            ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
            defer cancel()
            cmd := exec.CommandContext(ctx, "nmap", "-p-", "-sV", "-Pn", host)
            out, err := cmd.CombinedOutput()
            if err != nil {
                log.Printf("nmap error on %s: %v", host, err)
            }
            for _, m := range nmapRegex.FindAllStringSubmatch(string(out), -1) {
                port, _ := strconv.Atoi(m[1])
                ch <- models.PortService{Host: host, Port: port, Service: m[2], Version: m[3]}
            }
        }(h)
    }
    go func() {
        wg.Wait()
        close(ch)
    }()
    var services []models.PortService
    for svc := range ch {
        services = append(services, svc)
    }
    sort.Slice(services, func(i, j int) bool {
        if services[i].Host == services[j].Host {
            return services[i].Port < services[j].Port
        }
        return services[i].Host < services[j].Host
    })
    return services
}

// RunRecon orchestrates subfinder/amass and nmap based on target type.
func RunRecon(target string) (models.ReconResult, error) {
    var res models.ReconResult
    res.Target = target
    var hosts []string
    if net.ParseIP(target) == nil && !strings.Contains(target, "/") {
        subs, err := RunSubfinder(target)
        if err != nil {
            res.Error += fmt.Sprintf("subfinder error: %v; ", err)
        }
        amassHosts, err := RunAmassIntel(target)
        if err != nil {
            res.Error += fmt.Sprintf("amass enum error: %v; ", err)
        }
        res.Subdomains = subs
        hosts = append(subs, amassHosts...)
        hosts = append(hosts, target)
    } else {
        amassHosts, err := RunAmassIntel(target)
        if err != nil {
            res.Error += fmt.Sprintf("amass intel error: %v; ", err)
        }
        if strings.Contains(target, "/") {
            ips, _ := expandCIDR(target)
            hosts = append(hosts, ips...)
        } else {
            hosts = []string{target}
        }
        hosts = append(hosts, amassHosts...)
    }
    // dedupe
    seen := map[string]bool{}
    var uniq []string
    for _, h := range hosts {
        if !seen[h] {
            seen[h] = true
            uniq = append(uniq, h)
        }
    }
    res.Services = ScanNmap(uniq)
    return res, nil
}
