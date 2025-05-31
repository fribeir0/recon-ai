package services

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"os/exec"
	"strings"
)


func RunSubfinder(domain string) ([]string, error) {
	out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return []string{}, nil
	}
	return strings.Split(raw, "\n"), nil
}


func DiscoverHostsCIDR(cidr string) ([]string, error) {
	// Executa Naabu
	cmd := exec.Command("naabu", "-silent", "-sn", "-host", cidr)
	combined, err := cmd.CombinedOutput()
	raw := strings.TrimSpace(string(combined))

	// 1) Se Naabu listou ao menos um IP (stdout não vazio), retorna esses IPs, ignorando err.
	if raw != "" {
		ips := strings.Split(raw, "\n")
		return ips, nil
	}

	if err != nil {
		return []string{}, nil
	}

	// 3) Se stdout vazio e err == nil (pouco provável, mas por completude), também “nenhum host ativo”
	return []string{}, nil
}


func RunPortScanNaabu(hosts []string, ports string) (map[string][]string, error) {
	if len(hosts) == 0 {
		return nil, errors.New("nenhum host para escanear")
	}

	var args []string

	if ports == "" {
		args = []string{"-silent", "-l", "-", "-top-ports", "100"}
	} else {
		args = []string{"-silent", "-l", "-", "-p", ports}
	}
	

	cmd := exec.Command("naabu", args...)

	// Capturar stdout+stderr num buffer
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Escreve cada host (IP) na entrada do Naabu
	go func() {
		defer stdinPipe.Close()
		for _, ip := range hosts {
			stdinPipe.Write([]byte(ip + "\n"))
		}
	}()

	// Aguarda o Naabu terminar
	if err := cmd.Wait(); err != nil {
		// Mesmo que ele retorne exit code != 0, vamos parsear o que esteja no buffer
		if strings.TrimSpace(buf.String()) == "" {
			// Saída totalmente vazia => consideramos “nenhuma porta encontrada”
			return map[string][]string{}, nil
		}
		// Se buf tiver linhas “IP:PORT”, vamos parsear abaixo
	}

	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		// Se não veio nada, devolvemos map vazio
		return map[string][]string{}, nil
	}

	// Debug: logar tudo que veio no buffer (útil para ver o que exatamente o Naabu respondeu)
	log.Println("[DEBUG] Naabu saiu com:\n" + raw)

	// Agora dividimos cada linha “IP:PORT”
	result := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		ip := parts[0]
		porta := parts[1]
		result[ip] = append(result[ip], porta)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		log.Println("[WARN] erro ao ler saída do Naabu:", scanErr)
	}

	return result, nil
}
