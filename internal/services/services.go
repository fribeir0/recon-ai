package services

import (
    "bufio"
    "bytes"
    "fmt"
    "net"
    "os/exec"
    "regexp"
    "strings"
    "time"
)

// RunSubfinder finds subdomains for a domain.
func RunSubfinder(domain string) ([]string, error) {
    out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
    if err != nil {
        return nil, err
    }
    lines := strings.Split(strings.TrimSpace(string(out)), "\n")
    return lines, nil
}

// RunNaabu scans for open ports, returns lines "host:port".
func RunNaabu(target string) ([]string, error) {
    out, err := exec.Command("naabu", "-host", target).CombinedOutput()
    if err != nil {
        return nil, err
    }
    lines := strings.Split(strings.TrimSpace(string(out)), "\n")
    return lines, nil
}

// GrabHTTPX grabs the Server header via httpx.
func GrabHTTPX(url string) (string, error) {
    cmd := exec.Command("httpx", "-silent", "-status-code", "-server", "-url", url)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out
    if err := cmd.Run(); err != nil {
        return "", err
    }
    re := regexp.MustCompile(`\[\d+\]\s+\[([^\]]+)\]`)
    m := re.FindStringSubmatch(out.String())
    if len(m) == 2 {
        return m[1], nil
    }
    return "", nil
}

// GrabSSHBanner reads the SSH banner.
func GrabSSHBanner(host string, port int) (string, error) {
    addr := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
    if err != nil {
        return "", err
    }
    defer conn.Close()
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    reader := bufio.NewReader(conn)
    line, err := reader.ReadString('\n')
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(line), nil
}

// GrabBannerLine reads a single line banner for generic services.
func GrabBannerLine(host string, port int) (string, error) {
    return GrabSSHBanner(host, port)
}
