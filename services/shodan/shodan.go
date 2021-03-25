/* - service handler for shodan - */
package shodan

import (
	"flag"
	"fmt"
)

// - starting shodan scanning
// - shodan based method scanning
var (
	// - 0 is default value for flags
	nFavLink = flag.String("m", "", "Search by link favicon ico, example : https://localhost/favicon.ico")
)

func ShodanScan(key string) {
	flag.Parse()
	// - validate favLink, if not null will run methode with mmh3
	if *nFavLink != "" {
		fmt.Println(*nFavLink)
	}
}
