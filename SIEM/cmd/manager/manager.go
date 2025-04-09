package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"siem/pkg/alerta"
)

func main() {
	http.HandleFunc("/alert", primesteAlerta)

	port := ":58917"
	fmt.Println("[+] Managerul ascultă pe http://localhost" + port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func primesteAlerta(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Doar POST este permis", http.StatusMethodNotAllowed)
		return
	}

	var a alerta.Alerta
	err := json.NewDecoder(r.Body).Decode(&a)
	if err != nil {
		http.Error(w, "JSON invalid", http.StatusBadRequest)
		log.Println("[!] Alertă primită cu JSON invalid:", err)
		return
	}

	fmt.Println("\n================ ALERTĂ NOUĂ ================ ")
	fmt.Println("🛡️  Sistem   :", a.Sistem)
	fmt.Println("🚨 Tip       :", a.Tip)
	fmt.Println("📝 Detalii   :", a.Descriere)
	fmt.Println("⏱️  Timp      :", a.Timestamp)
	fmt.Println("==============================================")

	w.WriteHeader(http.StatusOK)
}
