package detectie

import "fmt"

func LoginuriRapide() {
	fmt.Println("")
}

// Aici o sa fie nevoie de o baza de date, ideaa funtiei este ca daca intr-un timp scurt exista multe incercari
// de login esuate (pe un dispozitiv) cel mai probabil este un atac de tip brute force

// posibil trigger: 5+loguri in mai putin de 30 de secunde
