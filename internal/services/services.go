package services

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
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

    "go-recon-masscan-nmap-universal/internal/models"
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

// RunSubfinder enumerates subdomains for a domain
func RunSubfinder(domain string) ([]string, error) {
    cmd := exec.Command("subfinder", "-d", domain, "-silent")
    out, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

// RunMasscan discovers open ports quickly on a host
func RunMasscan(host string) ([]int, error) {
    args := []string{"-p1-65535", "--rate", "10000", host, "--open", "--output-format", "json", "--output-file", "-"}
    cmd := exec.Command("masscan", args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    if err := cmd.Run(); err != nil {
        return nil, err
    }
    scanner := bufio.NewScanner(&out)
    var ports []int
    for scanner.Scan() {
        var entry struct {
            IP    string `json:"ip"`
            Ports []struct{ Port int } `json:"ports"`
        }
        if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
            continue
        }
        for _, p := range entry.Ports {
            ports = append(ports, p.Port)
        }
    }
    return ports, nil
}

// ScanNmapOptimized runs nmap -sV on grouped host:ports in batch
func ScanNmapOptimized(entries []models.PortService) []models.PortService {
    hostMap := make(map[string][]int)
    for _, e := range entries {
        hostMap[e.Host] = append(hostMap[e.Host], e.Port)
    }
    ch := make(chan models.PortService)
    var wg sync.WaitGroup
    for host, ports := range hostMap {
        wg.Add(1)
        go func(h string, ps []int) {
            defer wg.Done()
            sort.Ints(ps)
            portList := strings.Trim(strings.Replace(fmt.Sprint(ps), " ", ",", -1), "[]")
            ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
            defer cancel()
            args := []string{"-p", portList, "-sV", "-Pn", "-T4",
                "--version-intensity", "1", "--min-rate", "1000", "--max-retries", "1",
                "--host-timeout", "30s", h}
            out, err := exec.CommandContext(ctx, "nmap", args...).CombinedOutput()
            if err != nil {
                log.Printf("nmap error on %s: %v", h, err)
            }
            for _, m := range nmapRegex.FindAllStringSubmatch(string(out), -1) {
                port, _ := strconv.Atoi(m[1])
                ch <- models.PortService{Host: h, Port: port, Service: m[2], Version: m[3]}
            }
        }(host, ports)
    }
    go func() {
        wg.Wait()
        close(ch)
    }()
    var results []models.PortService
    for svc := range ch {
        results = append(results, svc)
    }
    return results
}

// RunRecon orchestrates full pipeline for any target type
func RunRecon(target string) (models.ReconResult, error) {
    var res models.ReconResult
    res.Target = target
    var hosts []string

    // domain: subfinder
    if ip := net.ParseIP(target); ip == nil && !strings.Contains(target, "/") {
        subs, err := RunSubfinder(target)
        if err != nil {
            res.Error += fmt.Sprintf("subfinder error: %v; ", err)
        }
        res.Subdomains = subs
        hosts = append(subs, target)
    } else if strings.Contains(target, "/") {
        ips, err := expandCIDR(target)
        if err != nil {
            return res, err
        }
        hosts = ips
    } else {
        hosts = []string{target}
    }

    // masscan on each host
    var initial []models.PortService
    for _, h := range hosts {
        ports, err := RunMasscan(h)
        if err != nil {
            // fallback to host-only nmap
            fmt.Println("masscan failed on", h, ":", err)
            continue
        }
        for _, p := range ports {
            initial = append(initial, models.PortService{Host: h, Port: p})
        }
    }

    // if no entries from masscan, fallback single nmap
    if len(initial) == 0 {
        return models.ReconResult{Target: target, Services: ScanNmapOptimized([]models.PortService{{Host: target, Port: 0}})}, nil
    }

    res.Services = ScanNmapOptimized(initial)
    return res, nil
}
