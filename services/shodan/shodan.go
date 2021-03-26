/* - service handler for shodan - */
package shodan

import (
	"flag"
	"log"

	"github.com/shadowscatcher/shodan/search"
)

// - starting shodan scanning
// - shodan based method scanning
var (
	// - 0 is default value for flags
	nFavLink = flag.String("ico", "", "Search by link favicon ico, example : https://localhost/favicon.ico")
	nDomain  = flag.String("domain", "", "Search by domain , example : https://google.com")
	nSubnet  = flag.String("subnet", "", "Search by subnet , example : 102.1.1.1/24")
	nProduct = flag.String("product", "", "Search by product , example : elastic")
)

// - pointer to drop shodan key
type ShodanKey struct {
	Key string
}

func ShodanScan(key string) {
	flag.Parse()
	shodanQuery := search.Query{}
	// - drop shodan key to struct and use pointer injection to distribute the key to another func

	var s ShodanKey
	s.Key = key // - add key to shodanKey pointer

	// - validate favLink, if not null will run methode with mmh3
	if *nFavLink != "" {
		log.Println("Search with link ico in : ", *nFavLink)
	}

	if *nProduct != "" {
		shodanQuery.Product = *nProduct // - add query based on product
		// - if no values match , will search by products only
		if *nDomain == "" && *nSubnet == "" {
			log.Println("Search with product in : ", *nProduct)
			s.Search(shodanQuery)
		}
	}

	// - validate domain , if not null will search methode with domain search based
	if *nDomain != "" {
		log.Println("Search with link domain in : ", *nDomain)
		shodanQuery.IP = *nDomain
		s.Search(shodanQuery)
	}

	// search by subnet like : 102.1.1.1/23
	if *nSubnet != "" {
		log.Println("Search with subnet in : ", *nSubnet)
		shodanQuery.Net = *nSubnet
		s.Search(shodanQuery)
	}

}
