package services

import (
    "bufio"
    "bytes"
    "context"
    "fmt"
    "io/ioutil"
    "log"
    "net"
    "os"
    "os/exec"
    "regexp"
    "sort"
    "strconv"
    "strings"
    "time"
    "go-recon-batch-nmap-pipeline/internal/models"
	"encoding/json"
)

var grepableRegex = regexp.MustCompile(`^Host: (\S+) .* Ports: (.+)`)

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

func RunSubfinder(domain string) ([]string, error) {
    cmd := exec.Command("subfinder", "-d", domain, "-silent")
    out, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}

func RunMasscan(host string) ([]models.PortService, error) {
    args := []string{"-p1-65535", "--rate", "10000", host, "--open", "--output-format", "json", "--output-file", "-"}
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
        line := scanner.Text()
        if err := json.Unmarshal([]byte(line), &entry); err != nil {
            continue
        }
        for _, p := range entry.Ports {
            svcs = append(svcs, models.PortService{Host: entry.IP, Port: p.Port})
        }
    }
    return svcs, nil
}

func ScanBatchNmap(entries []models.PortService) []models.PortService {
    hostSet := map[string]struct{}{}
    portSet := map[int]struct{}{}
    for _, e := range entries {
        hostSet[e.Host] = struct{}{}
        portSet[e.Port] = struct{}{}
    }
    var hosts []string
    var ports []int
    for h := range hostSet {
        hosts = append(hosts, h)
    }
    for p := range portSet {
        ports = append(ports, p)
    }
    sort.Strings(hosts)
    sort.Ints(ports)

    // write hosts to temp file
    file, _ := ioutil.TempFile("", "hosts")
    defer os.Remove(file.Name())
    for _, h := range hosts {
        file.WriteString(h + "\n")
    }
    file.Close()

    // build port list
    portList := strings.Trim(strings.Replace(fmt.Sprint(ports), " ", ",", -1), "[]")

    // run nmap once
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()
    args := []string{"-iL", file.Name(), "-p", portList, "-sV", "-Pn", "-T4",
        "--version-intensity", "1", "--min-rate", "1000", "--max-retries", "1",
        "--host-timeout", "30s", "-oG", "-"}
    cmd := exec.CommandContext(ctx, "nmap", args...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        log.Println("nmap batch error:", err)
    }

    var results []models.PortService
    scanner := bufio.NewScanner(bytes.NewReader(out))
    for scanner.Scan() {
        line := scanner.Text()
        if matches := grepableRegex.FindStringSubmatch(line); len(matches) == 3 {
            host := matches[1]
            portsDesc := matches[2]
            for _, pd := range strings.Split(portsDesc, ",") {
                parts := strings.Split(pd, "/")
                if len(parts) < 5 || parts[1] != "open" {
                    continue
                }
                port, _ := strconv.Atoi(parts[0])
                service := parts[4]
                version := ""
                if idx := strings.Index(pd, service+"/"); idx != -1 {
                    version = strings.Trim(pd[idx+len(service)+1:], " ")
                }
                results = append(results, models.PortService{
                    Host:    host,
                    Port:    port,
                    Service: service,
                    Version: version,
                })
            }
        }
    }
    return results
}

func RunRecon(target string) (models.ReconResult, error) {
    var res models.ReconResult
    res.Target = target
    var hosts []string
    if net.ParseIP(target) == nil && !strings.Contains(target, "/") {
        subs, err := RunSubfinder(target)
        if err != nil {
            res.Error += fmt.Sprintf("subfinder error: %v; ", err)
        }
        hosts = append(subs, target)
        res.Subdomains = subs
    } else if strings.Contains(target, "/") {
        ips, _ := expandCIDR(target)
        hosts = ips
    } else {
        hosts = []string{target}
    }
    var initial []models.PortService
    for _, h := range hosts {
        svcs, err := RunMasscan(h)
        if err != nil {
            res.Error += fmt.Sprintf("masscan error on %s: %v; ", h, err)
            continue
        }
        initial = append(initial, svcs...)
    }
    res.Services = ScanBatchNmap(initial)
    return res, nil
}