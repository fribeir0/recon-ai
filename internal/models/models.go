package models

// ReconRequest is the input payload.
type ReconRequest struct {
    Target string `json:"target"`
}

// PortService holds the result of scanning a port.
type PortService struct {
    Host    string `json:"host"`
    Port    int    `json:"port"`
    Service string `json:"service"`
    Version string `json:"version,omitempty"`
}

// ReconResult is the output payload.
type ReconResult struct {
    Target     string        `json:"target"`
    Subdomains []string      `json:"subdomains,omitempty"`
    Services   []PortService `json:"services"`
}
