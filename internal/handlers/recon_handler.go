
package handlers

import (
    "net"
    "strings"
    "net/http"

    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/services"
)

type ReconRequest struct {
    Target string `json:"target"`
}

type ReconResponse struct {
    Target     string   `json:"target"`
    Subdomains []string `json:"subdomains,omitempty"`
    Services   string   `json:"services,omitempty"`
    Nmap       string   `json:"nmap,omitempty"`
    Error      string   `json:"error,omitempty"`
}

func ReconHandler(c *gin.Context) {
    var req ReconRequest
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    res := ReconResponse{Target: req.Target}

    if net.ParseIP(req.Target) != nil || strings.Contains(req.Target, "/") {
        naabuOut, err := services.RunNaabu(req.Target)
        res.Services = naabuOut
        if err != nil {
            res.Error += "naabu error: " + err.Error() + "; "
        }

        nmapOut, err := services.RunNmap(req.Target)
        res.Nmap = nmapOut
        if err != nil {
            res.Error += "nmap error: " + err.Error() + "; "
        }

    } else {
        subs, err := services.RunSubfinder(req.Target)
        if err != nil {
            res.Error += "subfinder error: " + err.Error() + "; "
        } else {
            res.Subdomains = subs
        }

        var allNaabu, allNmap []string
        for _, sub := range subs {
            if strings.TrimSpace(sub) == "" {
                continue
            }
            naabuOut, err := services.RunNaabu(sub)
            if err != nil {
                res.Error += "naabu error on " + sub + ": " + err.Error() + "; "
            }
            allNaabu = append(allNaabu, naabuOut)

            nmapOut, err := services.RunNmap(sub)
            if err != nil {
                res.Error += "nmap error on " + sub + ": " + err.Error() + "; "
            }
            allNmap = append(allNmap, nmapOut)
        }

        res.Services = strings.Join(allNaabu, "\n")
        res.Nmap = strings.Join(allNmap, "\n")
    }

    c.JSON(http.StatusOK, res)
}
