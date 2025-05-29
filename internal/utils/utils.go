package utils

import (
    "log"
    "os"

    "github.com/go-resty/resty/v2"
    "go-recon-pipeline/internal/models"
)

func SendToN8n(result models.ReconResult) {
    url := os.Getenv("N8N_ENDPOINT")
    if url == "" {
        log.Println("N8N_ENDPOINT not defined")
        return
    }
    client := resty.New()
    resp, err := client.R().
        SetHeader("Content-Type", "application/json").
        SetBody(result).
        Post(url)
    if err != nil {
        log.Println("Error sending to n8n:", err)
        return
    }
    log.Printf("n8n response: %d", resp.StatusCode())
}
