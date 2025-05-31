package handlers

import (
    "log"
    "net"
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/services"
)

type ReconRequest struct {
    Target string `json:"target"`         // IP | CIDR | domínio
    Ports  string `json:"ports,omitempty"`// ex: "22", "80,443", "1-1000". Se vazio, Naabu usa top-ports.
}

func ReconHandler(c *gin.Context) {
    var req ReconRequest
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Requisição inválida: JSON mal formatado"})
        return
    }

    target := strings.TrimSpace(req.Target)
    ports := strings.TrimSpace(req.Ports)
    if target == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "O campo 'target' não pode estar vazio"})
        return
    }

    var hostsAtivos []string
    var err error

    // 1) Se for IP único (ParseIP != nil e sem "/"), considera ele como ativo
    if ip := net.ParseIP(target); ip != nil && !strings.Contains(target, "/") {
        log.Println("[INFO] IP único detectado:", target)
        hostsAtivos = []string{target}

    // 2) Se for CIDR (ex: "192.168.0.0/24")
    } else if _, _, cidrErr := net.ParseCIDR(target); cidrErr == nil {
        log.Println("[INFO] CIDR detectado:", target)
        hostsAtivos, err = services.DiscoverHostsCIDR(target)
        if err != nil {
            log.Println("[ERROR] Falha na descoberta de hosts CIDR:", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao descobrir hosts ativos no CIDR"})
            return
        }
        if len(hostsAtivos) == 0 {
            c.JSON(http.StatusOK, gin.H{
                "target":    target,
                "ativos":    []string{},
                "portas":    map[string][]string{},
                "total_ips": 0,
                "message":   "Nenhum host ativo encontrado nesse CIDR",
            })
            return
        }

    // 3) Caso contrário, tratar como domínio
    } else {
        log.Println("[INFO] Domínio detectado:", target)
        subs, subErr := services.RunSubfinder(target)
        if subErr != nil {
            log.Println("[ERROR] Falha no subfinder:", subErr)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao rodar subfinder"})
            return
        }
        if len(subs) == 0 {
            c.JSON(http.StatusOK, gin.H{
                "target":    target,
                "ativos":    []string{},
                "portas":    map[string][]string{},
                "total_ips": 0,
                "message":   "Nenhum subdomínio/dominio ativo encontrado",
            })
            return
        }

        // Resolve cada subdomínio via DNS e coleta só IPv4
        ipsMap := make(map[string]struct{})
        for _, sub := range subs {
            addrs, dnsErr := net.LookupIP(sub)
            if dnsErr != nil {
                log.Printf("[WARN] não conseguiu resolver %s: %v\n", sub, dnsErr)
                continue
            }
            for _, addr := range addrs {
                if addr.To4() != nil {
                    ipsMap[addr.String()] = struct{}{}
                }
            }
        }
        if len(ipsMap) == 0 {
            c.JSON(http.StatusOK, gin.H{
                "target":    target,
                "ativos":    []string{},
                "portas":    map[string][]string{},
                "total_ips": 0,
                "message":   "Nenhum IP ativo resolvido a partir dos subdomínios",
            })
            return
        }
        for ip := range ipsMap {
            hostsAtivos = append(hostsAtivos, ip)
        }
    }

    portasAbertas, scanErr := services.RunPortScanNaabu(hostsAtivos, ports)
    if scanErr != nil {
        log.Println("[ERROR] Falha no port scan com Naabu:", scanErr)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao rodar Naabu para portscan"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "target":    target,
        "ativos":    hostsAtivos,
        "portas":    portasAbertas,
        "total_ips": len(hostsAtivos),
    })
}
