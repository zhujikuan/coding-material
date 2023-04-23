package main

import (
	"fmt"
	"os"
)

func main() {
	var s string
	var sep string
	sep = " "
	for i := 0; i < len(os.Args); i += 1 {
		s += sep + os.Args[i]
	}

	fmt.Println(s)
}
