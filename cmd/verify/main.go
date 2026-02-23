package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/formats/note"
	tlogproof "github.com/transparency-dev/formats/proof"
	"github.com/transparency-dev/formats/witness"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var (
	rootPath          = flag.String("root-path", "", "Path to TUF root file")
	verifierPath      = flag.String("verifier-path", "", "Path to log verifier key")
	witnessPolicyPath = flag.String("witness-policy-path", "", "[optional] Path to witness policy")
)

func main() {
	flag.Parse()
	if *rootPath == "" {
		log.Fatalf("--root-path must be set")
	}
	if *verifierPath == "" {
		log.Fatalf("--verifier-path must be set")
	}

	rootData, err := os.ReadFile(*rootPath)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}
	var md metadata.Metadata[metadata.RootType]
	if err := json.Unmarshal(rootData, &md); err != nil {
		log.Fatalf("error unmarshaling root: %v", err)
		return
	}
	p, ok := md.UnrecognizedFields["tlog_proof"]
	if !ok {
		log.Fatalf("transparency log proof missing from TUF root")
	}
	delete(md.UnrecognizedFields, "tlog_proof") // Leaf hash will not include proof
	var tlogProof tlogproof.TLogProof
	if err := tlogProof.Unmarshal([]byte(p.(string))); err != nil {
		log.Fatalf("error unmarshaling tlog proof: %v", err)
	}

	canonicalizedRoot, err := cjson.EncodeCanonical(md)
	if err != nil {
		log.Fatalf("eror canonicalizing JSON: %v", err)
	}

	// Verify checkpoint
	verifier, err := os.ReadFile(*verifierPath)
	if err != nil {
		log.Fatalf("reading verifier file: %v", err)
	}
	vkey, err := note.NewVerifier(string(verifier))
	if err != nil {
		log.Fatalf("error creating verifier: %v", err)
	}
	verifiedCkpt, _, _, err := f_log.ParseCheckpoint(tlogProof.Checkpoint, vkey.Name(), vkey)
	if err != nil {
		log.Fatalf("tlog proof checkpoint could not be verified: %v", err)
	}

	// Verify witness signatures
	if *witnessPolicyPath != "" {
		witnessPolicy, err := os.ReadFile(*witnessPolicyPath)
		if err != nil {
			log.Fatalf("error reading witness policy: %v", err)
		}
		wg, err := witness.ParsePolicy(witnessPolicy)
		if err != nil {
			log.Fatalf("invalid witness policy: %v", err)
		}
		if !wg.Satisfied(tlogProof.Checkpoint) {
			log.Fatalf("tlog proof checkpoint could not be verified by witness policy")
		}
	}

	// Verify inclusion proof
	leafHash := rfc6962.DefaultHasher.HashLeaf(canonicalizedRoot)
	var hashes [][]byte
	for _, h := range tlogProof.Hashes {
		hashes = append(hashes, h[:])
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, tlogProof.Index, verifiedCkpt.Size, leafHash[:], hashes, verifiedCkpt.Hash); err != nil {
		log.Fatalf("error verifying inclusion proof: %v", err)
	}
}
