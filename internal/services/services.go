
package services

import (
    "log"
    "os/exec"
    "strings"
)

func RunSubfinder(domain string) []string {
    out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
    if err != nil {
        log.Println("Subfinder error:", err)
        return nil
    }
    return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func RunNaabu(target string) {
    out, err := exec.Command("naabu", "-host", target).CombinedOutput()
    if err != nil {
        log.Println("Naabu error:", err)
    }
    log.Println("Naabu output:", string(out))
}

func RunNmap(target string) {
    out, err := exec.Command("nmap", "-sV", target).CombinedOutput()
    if err != nil {
        log.Println("Nmap error:", err)
    }
    log.Println("Nmap output:", string(out))
}
