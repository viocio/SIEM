package monitor

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"siem/pkg/alerta"
	"siem/pkg/api"
)

func MonitorizeazaWindows() {
	fmt.Println("Funcția pentru Windows nu este încă implementată.")

	for {
		loguriLocaleWindows()
		loguriRemoteWindows()
		verificaIntegritateaWindows()
		time.Sleep(time.Second * 10)
	}
}

func loguriLocaleWindows() {
	cmd := exec.Command("powershell", "-Command", `
		Get-WinEvent -LogName Security -MaxEvents 100 |
		Where-Object { $_.Id -eq 4625 -or $_.Id -eq 4624 } |
		Select-Object -ExpandProperty Id
	`)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println("[WINDOWS] Eroare la citirea EventLog:", err)
		return
	}

	linii := strings.Split(out.String(), "\n")
	esecuriConsecutive := 0

	for _, linie := range linii {
		linie = strings.TrimSpace(linie)

		if linie == "4625" {
			esecuriConsecutive++
		} else if linie == "4624" {
			esecuriConsecutive = 0
		}

		if esecuriConsecutive == 3 {
			alertaNoua := alerta.Alerta{
				Sistem:    "windows",
				Tip:       "login_esuat",
				Descriere: "3 autentificări eșuate consecutive în EventLog",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)
			esecuriConsecutive = 0
		}
	}
}

func loguriRemoteWindows() {
	cmd := exec.Command("netstat", "-ano")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Println("[WINDOWS] Eroare la rularea netstat:", err)
		return
	}

	linii := strings.Split(out.String(), "\n")
	pragAvertizare := 7
	pragCritic := 10

	for _, linie := range linii {
		scor := calculeazaScorWindows(linie)
		if scor >= pragCritic {
			port := extragePort(linie)
			alerta := alerta.Alerta{
				Sistem:    "windows",
				Tip:       "remote_acces",
				Descriere: fmt.Sprintf("Conexiune suspectă pe portul %s (scor %d)", port, scor),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alerta)
		} else if scor >= pragAvertizare {
			alerta := alerta.Alerta{
				Sistem:    "windows",
				Tip:       "remote_acces",
				Descriere: "Activitate potențială de tip reverse shell",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alerta)
		}
	}
}

func calculeazaScorWindows(linie string) int {
	scor := 0
	linie = strings.ToLower(linie)

	if strings.Contains(linie, "established") {
		scor += 2
	}

	// Extragem PID-ul (ultimul câmp)
	campuri := strings.Fields(linie)
	if len(campuri) < 5 {
		return scor
	}
	pid := campuri[len(campuri)-1]

	// Luăm numele procesului
	cmd := exec.Command("tasklist", "/FI", "PID eq "+pid)
	output, err := cmd.Output()
	if err != nil {
		return scor
	}
	outputStr := strings.ToLower(string(output))

	if strings.Contains(outputStr, "powershell") || strings.Contains(outputStr, "cmd") ||
		strings.Contains(outputStr, "nc") || strings.Contains(outputStr, "ncat") ||
		strings.Contains(outputStr, "python") || strings.Contains(outputStr, "ssh") {
		scor += 5
	}

	// Verificăm dacă portul e neephemeral
	if port := extragePort(linie); port != "" {
		if num, err := strconv.Atoi(port); err == nil && num < 49000 {
			scor += 3
		}
	}

	return scor
}

func extragePort(linie string) string {
	campuri := strings.Fields(linie)
	if len(campuri) < 2 {
		return ""
	}
	adresa := campuri[1]
	parti := strings.Split(adresa, ":")
	if len(parti) > 1 {
		return parti[len(parti)-1]
	}
	return ""
}

func verificaIntegritateaWindows() {
	fisiere := []string{
		`C:\Windows\System32\drivers\etc\hosts`,
		`C:\Users\Public\Start Menu\Programs\Startup`,
		`C:\Windows\System32\config\SAM`,    // user accounts DB
		`C:\Windows\System32\config\SYSTEM`, // registry
		`C:\Windows\System32\Tasks`,         // task scheduler
	}

	for _, cale := range fisiere {
		info, err := os.Stat(cale)
		if err != nil {
			log.Printf("[INTEGRITATE] Nu pot accesa: %s — %v", cale, err)
			continue
		}

		modTime := info.ModTime()
		if time.Since(modTime) < 10*time.Minute {
			alerta := alerta.Alerta{
				Sistem:    "windows",
				Tip:       "modificare_fisier",
				Descriere: fmt.Sprintf("Fișier critic modificat recent: %s", cale),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alerta)
		}
	}
}
