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
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Failed password") {
			alertaNoua := alerta.Alerta{
				Sistem:    "linux",
				Tip:       "login_esuat",
				Descriere: line,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)

		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Eroare la citirea fișierului: %v", err)
	}
}
