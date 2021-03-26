package shodan

import (
	"context"
	"fmt"
	"log"
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

	client, _ := shodan.GetClient(key.Key, http.DefaultClient, true)
	ctx := context.Background()
	result, err := client.Search(ctx, search_query)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("found :", result.Total)

	for _, match := range result.Matches {

		// - next develop to search by mmh3
		if match.HTTP != nil && match.HTTP.Favicon != nil {
			fmt.Println(match.HTTP.Favicon.Hash)
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
			fmt.Println("exposed elastic:", match.IpAndPort())
			for indexName, index := range match.Elastic.Indices {
				fmt.Println(indexName, index.UUID)
			}
		}
	}
}
