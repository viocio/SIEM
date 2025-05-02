package storage

import (
	"database/sql"
	"fmt"
	"log"

	"siem/pkg/parser"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB(user, password, dbname string) {
	dsn := fmt.Sprintf("%s:%s@tcp(localhost:3306)/%s", user, password, dbname)

	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("[EROARE] Nu pot deschide conexiunea la baza de date:", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal("[EROARE] Nu mă pot conecta la MySQL:", err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS syslog (
		id INT AUTO_INCREMENT PRIMARY KEY,
		prival VARCHAR(64),
		timestamp VARCHAR(64),
		hostname VARCHAR(255),
		program VARCHAR(255),
		message TEXT
	);`
	if _, err := DB.Exec(createTable); err != nil {
		log.Fatal("[EROARE] Creare tabel eșuată:", err)
	}

	fmt.Println("[INFO] Conectat cu succes la baza de date MySQL.")
}

func SalveazaSyslog(mesaj parser.SyslogMessage) {
	if DB == nil {
		log.Println("[EROARE] Baza de date nu e inițializată.")
		return
	}

	_, err := DB.Exec(
		`INSERT INTO syslog (prival, timestamp, hostname, program, message) VALUES (?, ?, ?, ?)`,
		mesaj.Prival, mesaj.Timestamp, mesaj.Hostname, mesaj.Program, mesaj.Message,
	)
	if err != nil {
		log.Println("[EROARE] Inserare log eșuată:", err)
	}
}
