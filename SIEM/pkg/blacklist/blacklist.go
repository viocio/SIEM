package blacklist

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func ExtractIP(message string) string {
	words := strings.Split(message, " ")
	for i, word := range words {
		if word == "to" && i+1 < len(words) {
			return words[i+1]
		}
	}
	return ""
}

func AdaugaLaBlacklist(ip string) {
	path := "blacklist.txt"

	// Verificăm dacă IP-ul e deja în blacklist
	if alreadyBlacklisted(ip, path) {
		return
	}
	fmt.Println("sunt in fct blacklist")
	f, err := os.OpenFile(path, os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("[BLACKLIST] Eroare la deschidere blacklist.txt:", err)
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
	f, err := os.Open("D:/Facultate/Anul III/Sem II/TPI/SIEM/blacklist.txt")
	if err != nil {
		return false
	}

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		if scanner.Text() == ip {
			return true
		}
	}
	defer f.Close()
	return false
}
