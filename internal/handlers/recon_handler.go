package handlers

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "go-recon-nmap-concurrent/internal/models"
    "go-recon-nmap-concurrent/internal/services"
    "go-recon-nmap-concurrent/internal/utils"
)

func ReconHandler(c *gin.Context) {
    var req models.ReconRequest
    if err := c.BindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
        return
    }
    result, err := services.RunRecon(req.Target)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    go utils.SendToN8n(result)
    c.JSON(http.StatusOK, result)
}
