package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"siem/pkg/storage"
)

func main() {
	// Doar keyword
	keyword := flag.String("k", "", "Keyword de căutat în message")
	user := flag.String("user", "root", "Utilizator MySQL")
	pass := flag.String("pass", "parola", "Parola MySQL")
	dbname := flag.String("db", "siem", "Numele bazei de date")
	flag.Parse()

	if *keyword == "" {
		log.Fatal("⚠️  Folosește -k <keyword> pentru a căuta.")
	}

	storage.InitDB(*user, *pass, *dbname)

	query := `SELECT prival, timestamp, hostname, program, message FROM syslog WHERE message LIKE ?`
	rows, err := storage.DB.Query(query, "%"+*keyword+"%")
	if err != nil {
		log.Fatalf("[EROARE] La interogare: %v", err)
	}
	defer rows.Close()

	fmt.Println("🔍 Rezultate găsite:")
	fmt.Println(strings.Repeat("-", 90))

	for rows.Next() {
		var prival, timestamp, hostname, program, message string
		if err := rows.Scan(&prival, &timestamp, &hostname, &program, &message); err != nil {
			log.Println("[EROARE] La scanare:", err)
			continue
		}
		fmt.Printf("[%s] %s | %s | %s | %s\n", prival, timestamp, hostname, program, message)
	}
}
