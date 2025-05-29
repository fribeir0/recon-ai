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

func RunSubfinder(domain string) ([]string, error) {
    cmd := exec.Command("subfinder", "-d", domain, "-silent")
    out, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func RunMasscan(target string) ([]models.PortService, error) {
    args := []string{"-p1-65535", "--rate", "10000", target,
        "--open", "--output-format", "json", "--output-file", "-"}
    cmd := exec.Command("masscan", args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    if err := cmd.Run(); err != nil {
        return nil, err
    }
    scanner := bufio.NewScanner(&out)
    var svcs []models.PortService
    for scanner.Scan() {
        var entry struct {
            IP    string `json:"ip"`
            Ports []struct{ Port int } `json:"ports"`
        }
        if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
            continue
        }
        for _, p := range entry.Ports {
            svcs = append(svcs, models.PortService{Host: entry.IP, Port: p.Port})
        }
    }
    return svcs, nil
}

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

func RunRecon(target string) (models.ReconResult, error) {
    var res models.ReconResult
    res.Target = target

    // CIDR network: run masscan on entire block
    if strings.Contains(target, "/") {
        initial, err := RunMasscan(target)
        if err != nil {
            res.Error += fmt.Sprintf("masscan error: %v; ", err)
            return res, nil
        }
        res.Services = ScanNmapOptimized(initial)
        return res, nil
    }

    // Domain: subfinder + masscan
    var hosts []string
    if net.ParseIP(target) == nil {
        subs, err := RunSubfinder(target)
        if err != nil {
            res.Error += fmt.Sprintf("subfinder error: %v; ", err)
        }
        hosts = append(subs, target)
        res.Subdomains = subs
    } else {
        // single IP
        hosts = []string{target}
    }

    // masscan per host
    var initial []models.PortService
    for _, h := range hosts {
        svcs, err := RunMasscan(h)
        if err != nil {
            res.Error += fmt.Sprintf("masscan error on %s: %v; ", h, err)
            continue
        }
        initial = append(initial, svcs...)
    }

    res.Services = ScanNmapOptimized(initial)
    return res, nil
}
