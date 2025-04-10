package alerta

type Alerta struct {
	Sistem    string `json:"sistem"`
	Tip       string `json:"tip"`
	Descriere string `json:"descriere"`
	Timestamp string `json:"timestamp"`
}

/*
	^^^^
	||||

	Structura de date ce contine informatii despre o alerta care e trimisa la manager.
	Ce e in ghilimele dupa tipul de date, se numesc metadate si sunt folosite pentru a
	spune anumitor librarii cum sa se comporte la interactiunea cu aceste date.
*/
