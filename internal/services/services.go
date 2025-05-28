package services

import (
    "bufio"
    "bytes"
    "fmt"
    "log"
    "net"
    "os/exec"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "sync"

    "go-recon-masscan-nmap-optimized/internal/models"
)

var nmapRegex = regexp.MustCompile(`(?m)^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$`)

type HostPort struct {
    Host string
    Port int
}

// runCmd executes a command and returns its stdout lines.
func runCmd(name string, args ...string) ([]string, error) {
    cmd := exec.Command(name, args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    if err := cmd.Run(); err != nil {
        return nil, err
    }
    var lines []string
    scanner := bufio.NewScanner(&out)
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }
    return lines, nil
}

// RunSubfinder discovers subdomains (if target is domain).
func RunSubfinder(domain string) ([]string, error) {
    return runCmd("subfinder", "-d", domain, "-silent")
}

// RunMasscan uses masscan to quickly find open TCP ports.
func RunMasscan(target string) ([]HostPort, error) {
    lines, err := runCmd("masscan", target, "-p1-65535", "--rate", "10000", "--wait", "0", "-oL", "-")
    if err != nil {
        return nil, err
    }
    var hps []HostPort
    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) >= 4 && fields[0] == "open" && fields[1] == "tcp" {
            host := fields[2]
            port, err := strconv.Atoi(fields[3])
            if err == nil {
                hps = append(hps, HostPort{Host: host, Port: port})
            }
        }
    }
    return hps, nil
}

// ScanNmapConcurrent runs nmap -sV on aggregated ports per host in parallel.
func ScanNmapConcurrent(hps []HostPort) []models.PortService {
    var wg sync.WaitGroup
    ch := make(chan models.PortService)

    // group ports by host
    hostPorts := make(map[string][]int)
    for _, hp := range hps {
        hostPorts[hp.Host] = append(hostPorts[hp.Host], hp.Port)
    }

    for host, ports := range hostPorts {
        wg.Add(1)
        go func(h string, ps []int) {
            defer wg.Done()
            sort.Ints(ps)
            portList := strings.Trim(strings.Replace(fmt.Sprint(ps), " ", ",", -1), "[]")
            args := []string{"-p", portList, "-sV", "-Pn", "-T4", "--min-rate", "1000", "--max-retries", "1", "--host-timeout", "30s", h}
            out, err := exec.Command("nmap", args...).CombinedOutput()
            if err != nil {
                log.Printf("nmap error on %s: %v", h, err)
            }
            text := string(out)
            for _, m := range nmapRegex.FindAllStringSubmatch(text, -1) {
                port, _ := strconv.Atoi(m[1])
                ch <- models.PortService{
                    Host:    h,
                    Port:    port,
                    Service: m[2],
                    Version: m[3],
                }
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

// RunRecon orchestrates subfinder, masscan, and nmap.
func RunRecon(target string) (models.ReconResult, error) {
    var res models.ReconResult
    res.Target = target

    // determine hosts list
    var hosts []string
    if ip := net.ParseIP(target); ip != nil || strings.Contains(target, "/") {
        hosts = []string{target}
    } else {
        subs, err := RunSubfinder(target)
        if err != nil {
            log.Printf("subfinder error: %v", err)
            hosts = []string{target}
        } else {
            res.Subdomains = subs
            hosts = append(subs, target)
        }
    }

    // masscan for each host/range
    var allHPs []HostPort
    for _, h := range hosts {
        hps, err := RunMasscan(h)
        if err != nil {
            log.Printf("masscan error on %s: %v", h, err)
            continue
        }
        allHPs = append(allHPs, hps...)
    }

    // nmap version scan concurrently
    res.Services = ScanNmapConcurrent(allHPs)
    return res, nil
}
