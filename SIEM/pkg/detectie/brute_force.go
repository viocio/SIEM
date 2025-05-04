package detectie

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/api"
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
        AND timestamp >= NOW() - INTERVAL 1 MINUTE;
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
		ip := extractIP(msg)
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
			adaugaLaBlacklist(ip)
		}
	}
}

func extractIP(message string) string {
	words := strings.Split(message, " ")
	for i, word := range words {
		if word == "from" && i+1 < len(words) {
			return words[i+1]
		}
	}
	return ""
}

func adaugaLaBlacklist(ip string) {
	path := "blacklist.txt"

	// Verificăm dacă IP-ul e deja în blacklist
	if alreadyBlacklisted(ip, path) {
		return
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("[BLACKLIST] Eroare la deschidere blacklist.txt:", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(ip + "\n"); err != nil {
		log.Println("[BLACKLIST] Eroare la scriere:", err)
	} else {
		log.Printf("[BLACKLIST] IP %s adăugat în blacklist.txt\n", ip)
	}
}

func alreadyBlacklisted(ip, path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if scanner.Text() == ip {
			return true
		}
	}
	return false
}
