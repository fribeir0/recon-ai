package models

type ReconRequest struct {
    Target string `json:"target"`
}

type PortService struct {
    Port    int    `json:"port"`
    Service string `json:"service"`
    Version string `json:"version"`
}

type ReconResult struct {
    Target     string        `json:"target"`
    Subdomains []string      `json:"subdomains"`
    Services   []PortService `json:"services"`
}
