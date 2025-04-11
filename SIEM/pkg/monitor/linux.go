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
		time.Sleep(5 * time.Second) // se execută indiferent dacă a fost eroare sau nu
	}
}

func loguriRemote() {
	cmd := exec.Command("ss", "-tp")
	output, err := cmd.Output()
	if err != nil {
		log.Println("Eroare la ss -tp", err)
		return
	}
	linii := strings.Split(string(output), "\n")
	for _, linie := range linii {
		_ = linie
	}

	fmt.Println("Gata sefu")
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

// ✅ Citește offsetul din fișier (dacă există)
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

// ✅ Salvează offsetul curent într-un fișier
func salveazaOffset(cale string, offset int) {
	_ = os.WriteFile(cale, []byte(strconv.Itoa(offset)), 0644)
}
