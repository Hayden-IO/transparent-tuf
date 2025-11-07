package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"log"
	"os"

	tlogproof "github.com/Hayden-IO/transparent-tuf/internal/proof"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	logformat "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
)

var (
	logPath  = flag.String("log-path", "", "Path to log tiles, entry bundles and checkpoint")
	rootPath = flag.String("root-path", "", "Path to TUF root file")
)

func main() {
	flag.Parse()
	if *logPath == "" {
		log.Fatalf("--log-path must be set")
	}
	if *rootPath == "" {
		log.Fatalf("--root-path must be set")
	}
	ctx := context.Background()

	// Extract log index
	rootData, err := os.ReadFile(*rootPath)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}
	var md metadata.Metadata[metadata.RootType]
	if err := json.Unmarshal(rootData, &md); err != nil {
		log.Fatalf("error unmarshaling root: %v", err)
		return
	}
	// Entry index will always be one less than the version
	// since the log will only contain root metadata
	index := uint64(md.Signed.Version) - 1

	f := client.FileFetcher{
		Root: *logPath,
	}

	cpBody, err := f.ReadCheckpoint(ctx)
	if err != nil {
		log.Fatalf("error reading checkpoint: %v", err)
	}
	checkpoint := logformat.Checkpoint{}
	_, err = checkpoint.Unmarshal(cpBody)

	proofBuilder, err := client.NewProofBuilder(ctx, checkpoint.Size, f.ReadTile)
	if err != nil {
		log.Fatalf("error creating proof builder: %v", err)
	}
	inclusionProof, err := proofBuilder.InclusionProof(ctx, index)
	if err != nil {
		log.Fatalf("error creating inclusion proof: %v", err)
	}

	// Verify proof
	canonicalizedRoot, err := cjson.EncodeCanonical(md)
	if err != nil {
		log.Fatalf("error canonicalizing JSON TUF root: %v", err)
	}
	leafHash := rfc6962.DefaultHasher.HashLeaf(canonicalizedRoot)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, index, checkpoint.Size, leafHash[:], inclusionProof, checkpoint.Hash); err != nil {
		log.Fatalf("error verifying inclusion proof: %v", err)
	}

	// Add proof to TUF root
	var hashes [][sha256.Size]byte
	for _, h := range inclusionProof {
		hashes = append(hashes, [32]byte(h))
	}
	tlogProof := tlogproof.TLogProof{
		Index:      index,
		Hashes:     [][sha256.Size]byte(hashes),
		Checkpoint: cpBody,
	}
	marshaledProof := tlogProof.Marshal()
	md.UnrecognizedFields["tlog_proof"] = string(marshaledProof)

	rootWithProof, err := md.MarshalJSON()
	if err != nil {
		log.Fatalf("error marshaling root: %v", err)
	}
	var prettyJSONRoot bytes.Buffer
	if err := json.Indent(&prettyJSONRoot, rootWithProof, "", "\t"); err != nil {
		log.Fatalf("error pretty-printing JSON: %v", err)
	}
	if err := os.WriteFile(*rootPath, prettyJSONRoot.Bytes(), 0644); err != nil {
		log.Fatalf("error writing TUF root with inclusion proof: %v", err)
	}
}
