package services

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"os/exec"
	"strings"
)

// ----------------------------------------------------
// 1) RunSubfinder: dado um domínio, executa `subfinder -d <domínio> -silent`
//    Retorna slice de subdomínios (cada linha do stdout), ou erro se algo deu errado.
// ----------------------------------------------------
func RunSubfinder(domain string) ([]string, error) {
	out, err := exec.Command("subfinder", "-d", domain, "-silent").Output()
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return []string{}, nil
	}
	subs := strings.Split(raw, "\n")
	return subs, nil
}

// ----------------------------------------------------
// 2) DiscoverHostsCIDR: usa o Naabu em modo “host discovery” (-sn -silent -host <CIDR>)
//    - Executa: naabu -silent -sn -host <CIDR>
//    - Se houver IPs no stdout, retorna a lista, ignorando exit code ≠ 0.
//    - Se stdout estiver vazio, retorna slice vazio sem erro.
// ----------------------------------------------------
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


// ----------------------------------------------------
// 3) RunPortScanNaabu: dado um slice de hosts e string “ports” (ex: "80,443" ou "1-1000")
//    - Se “ports” estiver vazio, usa "-top-ports 100"; senão, "-p <ports>".
//    - Monta: naabu -silent -list - -top-ports 100  (ou "-p <ports>")
//    - Alimenta Naabu pelo stdin, lê stdout+stderr em buffer.
//    - Se exit code ≠ 0 mas houver conteúdo em buffer, ignora o erro e parseia.
//    - Se buffer vazio, retorna map vazio.
// ----------------------------------------------------
func RunPortScanNaabu(hosts []string, ports string) (map[string][]string, error) {
	if len(hosts) == 0 {
		return nil, errors.New("nenhum host para escanear")
	}

	var args []string
	if ports == "" {
		args = []string{"-silent", "-list", "-", "-top-ports", "100"}
	} else {
		args = []string{"-silent", "-list", "-", "-p", ports}
	}
	cmd := exec.Command("naabu", args...)

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

	go func() {
		defer stdinPipe.Close()
		for _, ip := range hosts {
			stdinPipe.Write([]byte(ip + "\n"))
		}
	}()

	if err := cmd.Wait(); err != nil {
		// Se buf não estiver vazio, ignora o erro; senão, retorna map vazio
		if strings.TrimSpace(buf.String()) == "" {
			return map[string][]string{}, nil
		}
	}

	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		return map[string][]string{}, nil
	}

	resultado := make(map[string][]string)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		ip := parts[0]
		porta := parts[1]
		resultado[ip] = append(resultado[ip], porta)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		log.Println("[WARN] erro ao ler saída do Naabu:", scanErr)
	}

	return resultado, nil
}

// ----------------------------------------------------
// 4) RunNmapServiceScan: dado um map[ip][]string (portas abertas por IP),
//    executa “nmap -sV -p <lista_de_portas> <ip>” para cada IP.
//    Retorna map[ip]string com o output bruto do Nmap. Se não houver portas,
//    atribui string vazia para aquele IP.
// ----------------------------------------------------
func RunNmapServiceScan(ipsPorts map[string][]string) (map[string]string, error) {
	results := make(map[string]string)

	for ip, portas := range ipsPorts {
		if len(portas) == 0 {
			results[ip] = ""
			continue
		}
		portsArg := strings.Join(portas, ",")
		cmd := exec.Command("nmap", "-sV", "-p", portsArg, ip)

		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf

		if err := cmd.Run(); err != nil {
			// Se Nmap falhar, anexa a mensagem de erro ao buffer
			buf.WriteString("\n[ERROR] nmap returned error: " + err.Error())
		}
		results[ip] = buf.String()
	}

	return results, nil
}