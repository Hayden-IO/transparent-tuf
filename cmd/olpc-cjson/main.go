package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var (
	filePath   = flag.String("input", "", "Path to TUF root file")
	outputPath = flag.String("output", "", "OLPC JSON canonicalization of TUF root")
)

func main() {
	flag.Parse()
	if *filePath == "" {
		log.Fatalf("--input must be set")
	}
	if *outputPath == "" {
		log.Fatalf("--output must be set")
	}
	f, err := os.ReadFile(*filePath)
	if err != nil {
		log.Fatalf("error readig file: %v", err)
	}
	var md metadata.Metadata[metadata.RootType]
	if err := json.Unmarshal(f, &md); err != nil {
		log.Fatalf("error unmarshaling root: %v", err)
		return
	}
	c, err := cjson.EncodeCanonical(md)
	if err != nil {
		log.Fatalf("error canonicalizing JSON: %v", err)
	}
	if err := os.WriteFile(*outputPath, c, 0644); err != nil {
		log.Fatalf("error writing file: %v", err)
	}
}
