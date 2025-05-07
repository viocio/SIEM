package monitor

import (
	"bufio"
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

func MonitorizeazaLinux() {
	logPath := "/home/apc/test_auth.log"
	offsetPath := "/home/apc/offset.txt"

	offset := citesteOffset(offsetPath)
	esecuriConsecutive := 0
	for {
		loguriLocale(offsetPath, logPath, &offset, &esecuriConsecutive)
		loguriRemote()
		verificaIntegritatea()
		time.Sleep(5 * time.Second) // se execută indiferent dacă a fost eroare sau nu
	}
}

func verificaIntegritatea() {
	fisiere := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/hosts",
		"/etc/rc.local",
		"/etc/profile",
		"/home/apc/.bashrc",
	}

	for _, cale := range fisiere {
		info, err := os.Stat(cale)
		if err != nil {
			log.Printf("[EROARE] Nu pot accesa: %s — %v", cale, err)
			continue
		}

		modTime := info.ModTime()
		// exemplu: considerăm suspicios dacă a fost modificat în ultimele 10 minute
		if time.Since(modTime) < 10*time.Minute {
			alerta := alerta.Alerta{
				Sistem:    "linux",
				Tip:       "modificare_fisier",
				Descriere: fmt.Sprintf("Fișier critic modificat recent: %s", cale),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alerta)
		}
	}
}

func loguriRemote() {
	data, err := os.ReadFile("/home/apc/test_ss.txt")
	// cmd := exec.Command("ss", "-tp")
	//output, err := cmd.Output()
	if err != nil {
		log.Println("Eroare la ss -tp", err)
		return
	}
	linii := strings.Split(string(data), "\n")
	pragAleta := 7
	pragCritic := 10
	for _, linie := range linii {
		scor := calculeazaScor(linie)
		if scor >= pragCritic {
			campuri := strings.Fields(linie)
			port := "unknown" // fallback default

			if len(campuri) >= 4 {
				adresa := campuri[3] // Local Address:Port
				parti := strings.Split(adresa, ":")
				if len(parti) > 1 {
					port = parti[len(parti)-1] // ultimul element e portul
				}
			}
			inchidePort(string(port))
			alertaNoua := alerta.Alerta{
				Sistem:    "linux",
				Tip:       "remote_acces",
				Descriere: "Conexiune netcat activa, se inchide portul:" + port,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)
		} else if scor >= pragAleta {
			alertaNoua := alerta.Alerta{
				Sistem:    "linux",
				Tip:       "remote_acces",
				Descriere: "Posibila conexiune remote",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			}
			api.TrimiteAlerta(alertaNoua)
		}
	}
}

func inchidePort(port string) {
	// Găsește PID-ul asociat portului
	cmd := exec.Command("lsof", "-i", ":"+port, "-t")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("[EROARE] Nu pot detecta procesul pe portul", port, ":", err)
		return
	}

	pidStr := strings.TrimSpace(string(output))
	if pidStr == "" {
		fmt.Println("[INFO] Nu există proces activ pe portul", port)
		return
	}

	// Omoară procesul
	killCmd := exec.Command("kill", "-9", pidStr)
	err = killCmd.Run()
	if err != nil {
		fmt.Println("[EROARE] Nu am putut termina procesul cu PID", pidStr, ":", err)
		return
	}

	fmt.Println("[ALERTĂ] Procesul pe portul", port, "a fost închis (PID:", pidStr+")")
}

func calculeazaScor(linie string) int {
	scor := 0

	linie = strings.ToLower(linie) // ca să nu conteze majusculele

	// Proces foarte suspect → scor mare instant
	if strings.Contains(linie, "nc") || strings.Contains(linie, "ncat") || strings.Contains(linie, "netcat") || strings.Contains(linie, "socat") {
		scor += 10
	}

	// Procese parțial suspecte (bash, sh, python), dar doar dacă e ESTAB
	if strings.Contains(linie, "bash") || strings.Contains(linie, "sh") || strings.Contains(linie, "python") {
		scor += 5
	}

	// Conexiune activă în general
	if strings.Contains(linie, "estab") {
		scor += 2
	}

	// Încercăm să extragem portul local
	campuri := strings.Fields(linie)
	if len(campuri) >= 5 {
		// Local Address:Port e la index 3
		adresa := campuri[3]
		// Separăm portul
		parti := strings.Split(adresa, ":")
		if len(parti) > 1 {
			portStr := parti[len(parti)-1]
			port, err := strconv.Atoi(portStr)
			if err == nil && port < 49000 {
				scor += 3
			}
		}
	}

	return scor
}

func loguriLocale(offsetPath string, logPath string, offset *int, esecuriConsecutive *int) {
	file, err := os.Open(logPath)
	if err != nil {
		log.Printf("Eroare la deschiderea fișierului: %v", err)
	} else {
		scanner := bufio.NewScanner(file)
		linieCurenta := 0

		for scanner.Scan() {
			linieCurenta++
			if linieCurenta <= *offset {
				continue
			}

			line := scanner.Text()

			if strings.Contains(line, "Failed password") {
				*esecuriConsecutive++
			} else if strings.Contains(line, "Accepted password") || strings.Contains(line, "session opened") {
				*esecuriConsecutive = 0
			}

			if *esecuriConsecutive == 3 {
				alertaNoua := alerta.Alerta{
					Sistem:    "linux",
					Tip:       "login_esuat",
					Descriere: "3 loginuri eșuate consecutive",
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				}
				api.TrimiteAlerta(alertaNoua)
				*esecuriConsecutive = 0
			}
		}

		*offset = linieCurenta
		salveazaOffset(offsetPath, *offset)

		defer file.Close()
	}
}

// Citește offsetul din fișier (dacă există)
func citesteOffset(cale string) int {
	data, err := os.ReadFile(cale)
	if err != nil {
		return 0
	}
	offset, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return offset
}

// Salvează offsetul curent într-un fișier
func salveazaOffset(cale string, offset int) {
	_ = os.WriteFile(cale, []byte(strconv.Itoa(offset)), 0644)
}
