package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/detectie"
	"siem/pkg/storage"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load("SIEM/.env")
	if err != nil {
		log.Fatal("Eroare la încărcarea fișierului .env")
	}

	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	db := os.Getenv("DB_NAME")

	storage.InitDB(user, pass, db)
	http.HandleFunc("/alert", primesteAlerta)
	go ruleazaDetectii()

	port := ":58917"
	fmt.Println("[+] Managerul ascultă pe http://localhost" + port)
	log.Fatal(http.ListenAndServe(port, nil))

}

func ruleazaDetectii() {
	for {
		detectie.BruteForce()
		detectie.Exfiltrare()
		detectie.PortScan()
		time.Sleep(10 * time.Second)
		fmt.Println("slaut")
	}
}

func primesteAlerta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { // ce se intampla daca cererea http de la agent nu estse de tip POST
		http.Error(w, "Doar POST este permis", http.StatusMethodNotAllowed)
		return
	}

	var a alerta.Alerta
	err := json.NewDecoder(r.Body).Decode(&a) // se decodeaza datele primite din request din JSON in formatul strcturei de date Alerta pe care am creat-o noi
	if err != nil {
		http.Error(w, "JSON invalid", http.StatusBadRequest)
		log.Println("[!] Alertă primită cu JSON invalid:", err)
		return
	}

	fmt.Println("\n================ ALERTĂ NOUĂ ================ ") // Se printeaza alerta
	fmt.Println("  Sistem   :", a.Sistem)
	fmt.Println(" Tip       :", a.Tip)
	fmt.Println(" Detalii   :", a.Descriere)
	fmt.Println(" Timp      :", a.Timestamp)
	fmt.Println("==============================================")

	w.WriteHeader(http.StatusOK)
}
