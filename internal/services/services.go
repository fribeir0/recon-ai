
package services

import (
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
    out, err := exec.Command("naabu", "-host", target).CombinedOutput()
    return string(out), err
}

func RunNmap(target string) (string, error) {
    out, err := exec.Command("nmap", "-sV", target).CombinedOutput()
    return string(out), err
}
