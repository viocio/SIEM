package detectie

import (
	"fmt"
	"log"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/api"
	"siem/pkg/blacklist"
	"siem/pkg/storage"
)

func BruteForce() {
	db := storage.DB
	if db == nil {
		log.Println("[BRUTE_FORCE] Baza de date nu e conectată.")
		return
	}

	query := `
        SELECT message FROM syslog
        WHERE (message LIKE '%Failed password%' OR message LIKE '%authentication failure%')
        AND timestamp >= NOW() - Interval 1 minute;
    `

	rows, err := db.Query(query)
	if err != nil {
		log.Println("[BRUTE_FORCE] Eroare la interogare:", err)
		return
	}
	defer rows.Close()

	ipCount := make(map[string]int)

	for rows.Next() {
		var msg string
		rows.Scan(&msg)
		ip := blacklist.ExtractIP(msg)
		if ip != "" {
			ipCount[ip]++
		}
	}

	for ip, count := range ipCount {
		if count >= 5 {
			alertaNoua := alerta.Alerta{
				Sistem:    "network",
				Tip:       "brute_force",
				Descriere: fmt.Sprintf("IP %s a avut %d loginuri eșuate în ultima minută.", ip, count),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)
			blacklist.AdaugaLaBlacklist(ip)
		}
	}
}
