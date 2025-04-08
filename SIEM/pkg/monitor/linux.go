package monitor

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func MonitorizeazaLinux() {
	logPath := "/var/log/auth.log" // Ai uitat / inițial ;)

	file, err := os.Open(logPath)
	if err != nil {
		log.Fatalf("Eroare la deschiderea fișierului %s: %v", logPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Failed password") {
			fmt.Println("[ALERTĂ] Login eșuat detectat:", line)
			// TODO: trimite alerta către SIEM
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Eroare la citirea fișierului: %v", err)
	}
}
