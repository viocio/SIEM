package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"siem/pkg/alerta"
)

func TrimiteAlerta(a alerta.Alerta) { // in Golang parametrii unei functii se scriu dupa tiparul : <nume_param> <tip_de_date>
	url := "http://192.168.101.43:58917/alert" // endpoint-ul managerului
	// se inlocuieste IP-ul cu IP-ul masinii pe care ruleaza managerul si portul cu portul ales in manager
	jsonData, err := json.Marshal(a)
	if err != nil {
		log.Printf("Eroare la serializarea alertei: %v", err)
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData)) // se trimite o cerere catre url, care e de tipul application/json, iar ultimul argument e efectiv acel json
	if err != nil {
		log.Printf("Eroare la trimiterea alertei: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("Alerta trimisă cu status: %s", resp.Status)
}
