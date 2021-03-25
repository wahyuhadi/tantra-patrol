/* - Trantra is tools to search artifact in public like (shodan) */
package main

import (
	"log"
	"tantra/constant"
	"tantra/services/shodan"
)

var (
	shodan_key bool = false /* - shodan_key default value is false */
)

func init() { // - initial function execute first before main
	// if shodan key found env will replace the variable shodan_key
	if constant.Shodan != "" {
		shodan_key = true
	}

	if !shodan_key {
		log.Println("- Shodan key not found in env")
	}
}

func main() {
	if shodan_key {
		shodan.ShodanScan(constant.Shodan)
	}
}
