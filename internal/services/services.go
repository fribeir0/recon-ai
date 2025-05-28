
package services

import (
    "log"
    "os/exec"
    "strings"
)

func RunSubfinder(domain string) ([]string, error) {
    out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
    if err != nil {
        return nil, err
    }
    lines := strings.Split(strings.TrimSpace(string(out)), "\n")
    return lines, nil
}

func RunNaabu(target string) (string, error) {
    out, err := exec.Command("naabu", "-host", target, "-nocolor").CombinedOutput()
    return string(out), err
}

func RunNmap(target string) (string, error) {
    // Primeiro tenta rodar sem -sV
    cmd := exec.Command("nmap", "-T4", "-Pn", "-F", target)
    out, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("Nmap fallback error: %v", err)
        return "Nmap fallback scan failed: " + err.Error() + "\nOutput:\n" + string(out), err
    }
    return string(out), nil
}
