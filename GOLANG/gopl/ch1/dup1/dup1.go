package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

func main() {
	counts := make(map[string]int)
	input := bufio.NewScanner(os.Stdin)

	for input.Scan() {
		counts[input.Text()]++
	}

	for line, n := range counts {
		fmt.Println(line + ":" + strconv.Itoa(n))
	}

}
