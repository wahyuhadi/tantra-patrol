/*- for constanta variable- */

package constant

import "os"

// Version tantra
var Versions string = "v0.0.1"

// - Shodan key for to search data for shodan
// - Variable serach is IP, mmh3(favicon hash)
var Shodan string = os.Getenv("SHODAN_KEY")
