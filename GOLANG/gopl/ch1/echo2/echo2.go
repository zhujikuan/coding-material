package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	var s, sep string
	s += "[ "
	sep = ", "
	for idx, arg := range os.Args {
		s += strconv.Itoa(idx) + ":" + arg + sep
	}
	s += "]"

	var s2 string = strings.Join(os.Args, ",")
	fmt.Println(s)
	fmt.Println(s2)
	fmt.Println(os.Args[1:1])
}
