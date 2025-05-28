package services

import (
    "bufio"
    "bytes"
    "fmt"
    "log"
    "os/exec"
    "regexp"
    "strconv"
    "strings"

    "go-recon-ai-modular/internal/models"
)

// RunRecon executa o reconhecimento com subfinder, naabu e nmap
func RunRecon(target string) (models.ReconResult, error) {
    subs, _ := runCommand("subfinder", "-d", target, "-silent")

    portsOutput, _ := runCommand("naabu", "-host", target, "-silent")
    var ports []int
    for _, line := range portsOutput {
        parts := strings.Split(line, ":")
        if len(parts) == 2 {
            if p, err := strconv.Atoi(parts[1]); err == nil {
                ports = append(ports, p)
            }
        }
    }

    var services []models.PortService
    if len(ports) > 0 {
        portsStr := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
        nmapOutput, _ := runCommand("nmap", "-p", portsStr, "-sV", "-Pn", target)

        serviceRegex := regexp.MustCompile(`(?m)^\d+/tcp\s+open\s+(\S+)\s+(.*)$`)
        for _, line := range nmapOutput {
            if matches := serviceRegex.FindStringSubmatch(line); len(matches) == 3 {
                portStr := strings.Split(line, "/")[0]
                port, _ := strconv.Atoi(portStr)
                services = append(services, models.PortService{
                    Port:    port,
                    Service: matches[1],
                    Version: matches[2],
                })
            }
        }
    }

    return models.ReconResult{
        Target:     target,
        Subdomains: subs,
        Services:   services,
    }, nil
}

func runCommand(command string, args ...string) ([]string, error) {
    cmd := exec.Command(command, args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out

    err := cmd.Run()
    if err != nil {
        log.Printf("Erro ao executar %s: %v", command, err)
        return nil, err
    }

    var results []string
    scanner := bufio.NewScanner(&out)
    for scanner.Scan() {
        results = append(results, strings.TrimSpace(scanner.Text()))
    }

    return results, nil
}
