package handlers

import (
    "log"
    "net"
    "strings"
    "net/http"

    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/services"
)

type ReconRequest struct {
    Target string `json:"target"`
}

func ReconHandler(c *gin.Context) {
    var req ReconRequest
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
        return
    }

    target := req.Target
    if net.ParseIP(target) != nil || strings.Contains(target, "/") {
        log.Println("[INFO] IP/CIDR detected:", target)
        services.RunNaabu(target)
        services.RunNmap(target)
    } else {
        log.Println("[INFO] Domain detected:", target)
        subs := services.RunSubfinder(target)
        for _, sub := range subs {
            services.RunNaabu(sub)
            services.RunNmap(sub)
        }
    }

    c.JSON(http.StatusOK, gin.H{"message": "Recon started"})
}
