package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

func main() {
	// Go detecteaza pe ce sistem de operare lucreaza si salveaza tipul in variabila GOOS din runtime, tip de date:char
	switch runtime.GOOS {
	case "linux":
		monitorizeazaLinux()
	case "windows":
		monitorizeazaWindows()
	default:
		log.Fatal("Sistemul de operare nu este suportat.")
	}
}

//    #####		Implementare SCRIPT pentru Linux 		######

func monitorizeazaLinux() {
	logPath := "var/log/auth.log"

	file, err := os.Open(logPath)
	if err != nil {
		log.Fatalf("Eroare la deschiderea fișierului %s: %v", logPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Caută liniile care indică un login eșuat
		if strings.Contains(line, "Failed password") {
			fmt.Println("[ALERTĂ] Login eșuat detectat:", line)
			// aici ai putea trimite alerta către serverul SIEM
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Eroare la citirea fișierului: %v", err)
	}

}

//	#####		Implementare SCRIPT pentru Windows 		######

func monitorizeazaWindows() {

}
