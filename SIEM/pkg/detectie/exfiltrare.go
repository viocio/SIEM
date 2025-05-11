package detectie

import (
	"fmt"
	"log"
	"strings"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/api"
	"siem/pkg/blacklist"
	"siem/pkg/storage"
)

func Exfiltrare() {
	db := storage.DB
	if db == nil {
		log.Println("[EXFIL] Conexiune lipsă la baza de date.")
		return
	}

	cuvinteCheie := []string{
		"data exfiltration",
		"suspicious upload",
		"large data transfer",
		"possible exfil",
		"external ftp upload",
		"unknown outbound connection",
	}

	rows, err := db.Query(`
	SELECT prival, timestamp, hostname, program, message 
	FROM syslog
	WHERE timestamp >= NOW() - Interval 1 minute;
	`)
	if err != nil {
		log.Println("[EXFIL] Eroare la interogarea bazei de date:", err)
		return
	}

	defer rows.Close()

	for rows.Next() {
		var prival, timestamp, hostname, program, message string
		err := rows.Scan(&prival, &timestamp, &hostname, &program, &message)
		if err != nil {
			continue
		}

		lowerMsg := strings.ToLower(message)
		for _, keyword := range cuvinteCheie {
			if strings.Contains(lowerMsg, keyword) {
				alertaNoua := alerta.Alerta{
					Sistem:    hostname,
					Tip:       "exfiltrare",
					Descriere: "Posibilă exfiltrare de date: " + message,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}
				fmt.Println(lowerMsg)
				ip := blacklist.ExtractIP(lowerMsg)

				blacklist.AdaugaLaBlacklist(ip)
				api.TrimiteAlerta(alertaNoua)
				break
			}
		}
	}
}
