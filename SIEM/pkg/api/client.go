package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"siem/pkg/alerta"
)

func TrimiteAlerta(a alerta.Alerta) {
	url := "http://192.168.229.43:58917/alert" // endpoint-ul managerului

	jsonData, err := json.Marshal(a)
	if err != nil {
		log.Printf("Eroare la serializarea alertei: %v", err)
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Eroare la trimiterea alertei: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("Alerta trimisă cu status: %s", resp.Status)
}
