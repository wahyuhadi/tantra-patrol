package shodan

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"

	//import shodan client
	"github.com/shadowscatcher/shodan"
	"github.com/shadowscatcher/shodan/search"
)

// - Search data based on domain

func (key *ShodanKey) Search(query search.Query) {
	search_query := search.Params{
		Page:  1,
		Query: query,
	}
	// search_query.Page++
	client, _ := shodan.GetClient(key.Key, http.DefaultClient, true)
	ctx := context.Background()
	result, err := client.Search(ctx, search_query)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("[+]found :", result.Facets)
	TotalPage := int(math.Ceil(float64(result.Total) / 100))

	for i := 1; i < TotalPage; i++ {

		// - page 1 will use the old data
		// - and page 2 will re-request data from shodan
		if i != 1 { // - makesure i not equel one
			client, _ := shodan.GetClient(key.Key, http.DefaultClient, true)
			ctx := context.Background()
			search_query.Page = uint(i)
			result, err = client.Search(ctx, search_query)
			if err != nil {
				log.Fatal(err)
			}
		}

		for _, match := range result.Matches {

			// - next develop to search by mmh3

			if match.HTTP != nil && match.HTTP.Favicon != nil {
				fmt.Println(match.IpAndPort())
				// fmt.Println(match.HTTP.Favicon.Hash)
			}

			// - find if mongodb open
			if match.MongoDB != nil && !match.MongoDB.Authentication {
				// - do manual check
				fmt.Println("exposed mongodb:", match.IpAndPort())
				databases := match.MongoDB.ListDatabases.Databases
				fmt.Println("databases:", len(databases), "size:", match.MongoDB.ListDatabases.TotalSize)
				for _, db := range databases {
					for _, collectionName := range db.Collections {
						fmt.Println(collectionName)
					}
				}
			}

			// validate if ssl is expired
			if match.SSL != nil && match.SSL.Cert.Expired {
				fmt.Println("expired certificate:", match.IpAndPort())
			}

			// find if  elastic is open
			if match.Elastic != nil {
				// - do manual check
				fmt.Println("[+] Exposed elastic 	: ", match.IpAndPort())
				for indexName, index := range match.Elastic.Indices {
					fmt.Println("[-] Found Index : ", indexName, index.UUID)
				}
			}

			// - Verify vuln
			if match.Vulns != nil {
				for _, item := range match.Vulns {
					// - verify by shodan
					if item.Verified {
						fmt.Println("\n[+] Verified By Shodan  - CVSS 	: ", item.CVSS)
						fmt.Println("[+] Verified By Shodan  - IP 	: ", match.IpAndPort())
						fmt.Println("[+] Verified By Shodan  - Summary 	: ", item.Summary)
					}

					fmt.Println("\n[+] Not Verified By Shodan  - CVSS    : ", item.CVSS)
					fmt.Println("[+] Not Verified By Shodan  - IP      : ", match.IpAndPort())
					fmt.Println("[+] Not Verified By Shodan  - Summary : ", item.Summary)
				}
			}
		}
	}
}
