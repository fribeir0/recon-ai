package main

import (
    "log"
    "os"

    "github.com/gin-gonic/gin"
    "go-recon-ai-modular/internal/handlers"
)

func main() {
    r := gin.Default()
    r.POST("/recon", handlers.ReconHandler)

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Server starting on port %s", port)
    r.Run(":" + port)
}
