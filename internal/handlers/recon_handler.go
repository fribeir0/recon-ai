
package handlers

import (
    "encoding/json"
    "log"
    "net"
    "net/http"
    "strings"

    "go-recon-ai/internal/services"
)

type ReconRequest struct {
    Target string `json:"target"`
}

func ReconHandler(w http.ResponseWriter, r *http.Request) {
    var req ReconRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
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

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Recon started"))
}
