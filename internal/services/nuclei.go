package services

import (
    "bufio"
    "bytes"
    "log"
    "os/exec"
    "strings"
)

// RunNuclei executa o nuclei em um alvo específico
func RunNuclei(target string, templates []string) ([]string, error) {
    args := []string{"-u", target, "-silent"}
    if len(templates) > 0 {
        args = append(args, "-t", strings.Join(templates, ","))
    }

    cmd := exec.Command("nuclei", args...)
    var out bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &out

    err := cmd.Run()
    if err != nil {
        log.Println("Erro ao rodar nuclei:", err)
        return nil, err
    }

    var results []string
    scanner := bufio.NewScanner(&out)
    for scanner.Scan() {
        results = append(results, scanner.Text())
    }

    return results, nil
}
