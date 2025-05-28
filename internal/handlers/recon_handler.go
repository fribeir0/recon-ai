package handlers

import (
    "fmt"
    "net"
    "strconv"
    "strings"
    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/models"
    "go-recon-ai-modular/internal/services"
    "go-recon-ai-modular/internal/utils"
)

func ReconHandler(c *gin.Context) {
    var req models.ReconRequest
    if err := c.BindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid JSON"})
        return
    }
    resp := models.ReconResponse{Target: req.Target}

    isDomain := !strings.Contains(req.Target, "/") && net.ParseIP(req.Target) == nil
    var hosts []string
    if isDomain {
        subs, err := services.RunSubfinder(req.Target)
        if err != nil {
            resp.Error = "subfinder error: " + err.Error()
        } else {
            resp.Subdomains = subs
            hosts = subs
        }
        hosts = append(hosts, req.Target)
    } else {
        hosts = []string{req.Target}
    }

    for _, host := range hosts {
        ports, err := services.RunNaabu(host)
        if err != nil {
            resp.Error += " naabu error on " + host + ": " + err.Error()
            continue
        }
        for _, line := range ports {
            parts := strings.Split(line, ":")
            if len(parts) != 2 {
                continue
            }
            port, err := strconv.Atoi(parts[1])
            if err != nil {
                continue
            }
            svc := models.PortService{Host: parts[0], Port: port}
            if port == 80 || port == 443 || port == 8080 || port == 8000 {
                scheme := "http"
                if port == 443 {
                    scheme = "https"
                }
                url := fmt.Sprintf("%s://%s:%d", scheme, parts[0], port)
                version, err := services.GrabHTTPX(url)
                if err == nil {
                    svc.Service = "http"
                    svc.Version = version
                } else {
                    svc.Service = "http"
                }
            } else if port == 22 {
                banner, err := services.GrabSSHBanner(parts[0], port)
                if err == nil {
                    svc.Service = "ssh"
                    svc.Version = banner
                } else {
                    svc.Service = "ssh"
                }
            } else {
                ban, err := services.GrabBannerLine(parts[0], port)
                if err == nil {
                    svc.Service = "tcp"
                    svc.Version = ban
                } else {
                    svc.Service = "tcp"
                }
            }
            resp.Services = append(resp.Services, svc)
        }
    }

    go utils.SendToN8n(resp)
    c.JSON(200, resp)
}
