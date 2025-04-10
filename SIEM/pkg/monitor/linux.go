package monitor

import (
	"bufio"
	"log"
	"os"
	"strings"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/api"
)

func MonitorizeazaLinux() {
	logPath := "/home/apc/test_auth.log" // Path catre fisierul de stocare al logurilor locale

	file, err := os.Open(logPath)
	if err != nil {
		log.Fatalf("Eroare la deschiderea fișierului %s: %v", logPath, err) // gestionare eroare
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	esecuriConsecutive := 0
	// TODO: sa faci un scan periodic la fisier, nu doar odata
	// scanul sa inceapa de la ultima linie a fisierului
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Failed password") {
			esecuriConsecutive++
		}

		// Resetare doar la login reușit
		if strings.Contains(line, "Accepted password") || strings.Contains(line, "session opened") {
			esecuriConsecutive = 0
		}

		if esecuriConsecutive == 3 {
			alertaNoua := alerta.Alerta{
				Sistem:    "linux",
				Tip:       "login_esuat",
				Descriere: "3 loginuri eșuate consecutive",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Eroare la citirea fișierului: %v", err)
	}
}
