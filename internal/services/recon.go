package services

import (
    "bufio"
    "bytes"
    "log"
    "net"
    "os/exec"
    "regexp"
    "strconv"
    "strings"
    "sync"

    "go-recon-nmap-concurrent/internal/models"
)

var nmapRegex = regexp.MustCompile(`(?m)^(\d+)/tcp\s+open\s+(\S+)\s+(.*)$`)

// runCommand executes a system command and returns its stdout lines.
func runCommand(command string, args ...string) ([]string, error) {
    cmd := exec.Command(command, args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    if err := cmd.Run(); err != nil {
        return nil, err
    }
    scanner := bufio.NewScanner(&out)
    var lines []string
    for scanner.Scan() {
        lines = append(lines, strings.TrimSpace(scanner.Text()))
    }
    return lines, nil
}

type HostPort struct {
    Host string
    Port int
}

// ScanNmapConcurrent runs nmap -sV -Pn on each host:port concurrently.
func ScanNmapConcurrent(hps []HostPort) []models.PortService {
    var wg sync.WaitGroup
    ch := make(chan models.PortService)

    for _, hp := range hps {
        wg.Add(1)
        go func(hp HostPort) {
            defer wg.Done()
            args := []string{"-p", strconv.Itoa(hp.Port), "-sV", "-Pn", hp.Host}
            out, err := exec.Command("nmap", args...).CombinedOutput()
            if err != nil {
                log.Printf("nmap error on %s:%d: %v", hp.Host, hp.Port, err)
            }
            text := string(out)
            matches := nmapRegex.FindAllStringSubmatch(text, -1)
            for _, m := range matches {
                port, _ := strconv.Atoi(m[1])
                ch <- models.PortService{
                    Host:    hp.Host,
                    Port:    port,
                    Service: m[2],
                    Version: m[3],
                }
            }
        }(hp)
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

// RunRecon orchestrates subfinder, naabu and nmap.
func RunRecon(target string) (models.ReconResult, error) {
    var result models.ReconResult
    result.Target = target

    // determine hosts list
    var hosts []string
    if ip := net.ParseIP(target); ip != nil || strings.Contains(target, "/") {
        hosts = []string{target}
    } else {
        subs, err := runCommand("subfinder", "-d", target, "-silent")
        if err != nil {
            log.Println("subfinder error:", err)
        } else {
            result.Subdomains = subs
            hosts = append(subs, target)
        }
    }

    // collect host:port list
    var hps []HostPort
    for _, host := range hosts {
        ports, err := runCommand("naabu", "-host", host, "-silent")
        if err != nil {
            log.Printf("naabu error on %s: %v", host, err)
            continue
        }
        for _, line := range ports {
            parts := strings.Split(line, ":")
            if len(parts) != 2 {
                continue
            }
            if port, err := strconv.Atoi(parts[1]); err == nil {
                hps = append(hps, HostPort{Host: parts[0], Port: port})
            }
        }
    }

    // run nmap scan concurrently
    result.Services = ScanNmapConcurrent(hps)
    return result, nil
}
