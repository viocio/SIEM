package detectie

import (
	"log"
	"regexp"
	"siem/pkg/alerta"
	"siem/pkg/api"
	"siem/pkg/blacklist"
	"siem/pkg/storage"
	"strings"
	"time"
)

func PortScan() {
	db := storage.DB
	if db == nil {
		log.Println("[PORTSCAN] Baza de date nu e conectată.")
		return
	}

	query := `
		SELECT message FROM syslog
		WHERE timestamp < NOW() 
	`

	rows, err := db.Query(query)
	if err != nil {
		log.Println("[PORTSCAN] Eroare la interogare:", err)
		return
	}
	defer rows.Close()

	count := make(map[string]int)
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			continue
		}

		lower := strings.ToLower(msg)
		if strings.Contains(lower, "connection attempt") ||
			strings.Contains(lower, "port scan") ||
			strings.Contains(lower, "probing") {
			ipuri := ipRegex.FindAllString(msg, -1)

			if len(ipuri) > 0 {
				ip := ipuri[0]
				count[ip]++
			}
		}
	}

	prag := 5
	for ip, nr := range count {
		if nr >= prag {
			alertaNoua := alerta.Alerta{
				Sistem:    "reteaua",
				Tip:       "port_scan",
				Descriere: "Detectat port scanning de la IP: " + ip,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)

			blacklist.AdaugaLaBlacklist(ip)
		}
	}
}
