package handlers

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/models"
    "go-recon-ai-modular/internal/services"
    "go-recon-ai-modular/internal/utils"
)

// ReconHandler lida com a requisição de reconhecimento
func ReconHandler(c *gin.Context) {
    var req models.ReconRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido"})
        return
    }

    result, err := services.RunRecon(req.Target)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro no reconhecimento"})
        return
    }

    go utils.SendToN8n(result)
    c.JSON(http.StatusOK, result)
}
