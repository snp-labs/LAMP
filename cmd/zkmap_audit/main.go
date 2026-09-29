// Command zkmap_audit displays the zkMaP specification audit results
// Usage:
//
//	zkmap_audit          - Display human-readable report
//	zkmap_audit -json    - Export results as JSON
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"example.com/lamp/crypto/zkmap_audit"
)

func main() {
	jsonFlag := flag.Bool("json", false, "Export results as JSON")
	flag.Parse()
	summary := zkmap_audit.GenerateSummary()

	if *jsonFlag {
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("zkMaP diagnostic: %s\n", summary.Summary)
		for _, result := range summary.Results {
			fmt.Printf("[%s] passed=%t %s\n", result.Category, result.Passed, result.Name)
		}
	}
	if !summary.AllPassed {
		os.Exit(1)
	}
}
