package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println(r)
		w.Write([]byte("Hello World"))
	})
	http.ListenAndServe(":7777", nil)
}
