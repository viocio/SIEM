package detectie

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/api"
)

func ReverseShell() {
	cmd := exec.Command("ss", "-tp")
	output, err := cmd.Output()
	if err != nil {
		log.Println("[REVERSE] Eroare la execuția ss -tp:", err)
		return
	}

	linii := strings.Split(string(output), "\n")
	prag := 7

	for _, linie := range linii {
		scor := calculeazaScorSuspiciune(linie)
		if scor >= prag {
			port := extragePortLocal(linie)
			alertaNoua := alerta.Alerta{
				Sistem:    "linux",
				Tip:       "remote_access",
				Descriere: fmt.Sprintf("Conexiune suspectă detectată pe port %s", port),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)

			// blochează portul dacă e clar dubios
			// blocheazaPort(port) // doar dacă e critic
		}
	}
}

func calculeazaScorSuspiciune(linie string) int {
	scor := 0
	linie = strings.ToLower(linie)

	if strings.Contains(linie, "nc") || strings.Contains(linie, "netcat") || strings.Contains(linie, "socat") {
		scor += 10
	}
	if strings.Contains(linie, "bash") || strings.Contains(linie, "sh") || strings.Contains(linie, "python") {
		scor += 5
	}
	if strings.Contains(linie, "estab") {
		scor += 2
	}
	// verificare port
	campuri := strings.Fields(linie)
	if len(campuri) >= 5 {
		adresa := campuri[3]
		parti := strings.Split(adresa, ":")
		if len(parti) > 1 {
			portStr := parti[len(parti)-1]
			port, err := strconv.Atoi(portStr)
			if err == nil && port < 49000 {
				scor += 3
			}
		}
	}
	return scor
}

func extragePortLocal(linie string) string {
	campuri := strings.Fields(linie)
	if len(campuri) >= 4 {
		adresa := campuri[3]
		parti := strings.Split(adresa, ":")
		return parti[len(parti)-1]
	}
	return "necunoscut"
}
