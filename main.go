package main

import (
    "log"
    "os"

    "github.com/gin-gonic/gin"
    "go-recon-pipeline/internal/handlers"
)

func main() {
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    log.Printf("Server starting on port %s", port)
    r := gin.Default()
    r.POST("/recon", handlers.ReconHandler)
    r.Run(":" + port)
}
