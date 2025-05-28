package models

type ReconRequest struct {
    Target string `json:"target"`
}

type PortService struct {
    Host    string `json:"host"`
    Port    int    `json:"port"`
    Service string `json:"service"`
    Version string `json:"version,omitempty"`
}

type ReconResponse struct {
    Target     string        `json:"target"`
    Subdomains []string      `json:"subdomains,omitempty"`
    Services   []PortService `json:"services,omitempty"`
    Error      string        `json:"error,omitempty"`
}
