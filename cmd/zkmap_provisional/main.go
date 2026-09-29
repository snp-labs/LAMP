package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"example.com/lamp/crypto/zkmap_provisional"
)

func main() {
	n := flag.Int("n", 8, "matrix dimension n")
	repetitions := flag.Int("repetitions", 1, "number of timing attempts")
	threads := flag.Int("threads", runtime.NumCPU(), "number of threads")
	mode := flag.String("mode", "integers", "interpolation mode: integers or fft")
	output := flag.String("output", "", "output JSONL file (required); refuses overwrite")
	maxElements := flag.Int("max-matrix-elements", 1<<20, "maximum matrix element count")
	flag.Parse()

	if *output == "" {
		log.Fatalf("flag -output is required")
	}
	if *n < 2 {
		log.Fatalf("n must be >= 2, got %d", *n)
	}
	if *repetitions < 1 {
		log.Fatalf("repetitions must be >= 1, got %d", *repetitions)
	}
	if *threads < 1 {
		log.Fatalf("threads must be >= 1, got %d", *threads)
	}

	var interpMode zkmap_provisional.InterpolationMode
	if *mode == "fft" {
		interpMode = zkmap_provisional.FFTRoots
	} else if *mode == "integers" {
		interpMode = zkmap_provisional.IntegerNodes
	} else {
		log.Fatalf("unknown interpolation mode: %s", *mode)
	}

	config := zkmap_provisional.ProverConfig{
		N:                 *n,
		Mode:              interpMode,
		NumThreads:        *threads,
		MaxMatrixElements: *maxElements,
	}

	if err := config.Validate(); err != nil {
		log.Fatalf("config validation: %v", err)
	}

	_, err := os.Stat(*output)
	if err == nil {
		log.Fatalf("output file already exists: %s", *output)
	}
	if !os.IsNotExist(err) {
		log.Fatalf("check output file: %v", err)
	}

	parentDir := filepath.Dir(*output)
	if parentDir != "" && parentDir != "." {
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			log.Fatalf("create directory: %v", err)
		}
	}

	f, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatalf("create output file: %v", err)
	}
	defer f.Close()

	fmt.Printf("zkmap_provisional: n=%d, repetitions=%d, mode=%s, threads=%d\n", *n, *repetitions, *mode, *threads)
	fmt.Printf("Output: %s\n\n", *output)

	fmt.Printf("Preparing prover (setup and preprocessing)...\n")
	startPrep := time.Now()
	prover, err := zkmap_provisional.NewPreparedProver(config)
	if err != nil {
		log.Fatalf("prepare prover: %v", err)
	}
	prepTime := time.Since(startPrep).Seconds()
	fmt.Printf("Setup/preprocessing complete: %.3fs\n\n", prepTime)

	successCount := 0
	for rep := 0; rep < *repetitions; rep++ {
		fmt.Printf("Attempt %d/%d...\n", rep+1, *repetitions)

		result, err := prover.Prove()
		if err != nil {
			log.Fatalf("prover error on attempt %d: %v", rep+1, err)
		}

		jsonBytes, err := json.Marshal(result)
		if err != nil {
			log.Fatalf("marshal result: %v", err)
		}

		_, err = f.WriteString(string(jsonBytes) + "\n")
		if err != nil {
			log.Fatalf("write result: %v", err)
		}

		if result.Error == "" {
			successCount++
			fmt.Printf("  Attempt %d complete. Online: %.3fs, Total: %.3fs\n",
				rep+1,
				result.TimingBreakdown.OnlineSeconds,
				result.TimingBreakdown.TotalSeconds,
			)
			fmt.Printf("    Challenge Y: %s (first 16 chars)\n", result.ChallengeYHex[:16])
			fmt.Printf("    Mode: %s, Remainder zero: %v, Witness exists: %v\n",
				result.InterpolationMode,
				result.RemainderIsZero,
				result.WitnessPolynomialExists,
			)
			fmt.Printf("    Pairing accepted: %v, Mu dot consistent: %v\n",
				result.LiteralPairingAccepted,
				result.MuDotConsistent,
			)
		} else {
			fmt.Printf("  Attempt %d FAILED: %s\n", rep+1, result.Error)
		}
		fmt.Println()
	}

	fmt.Printf("Results: %d/%d successful attempts written to %s\n", successCount, *repetitions, *output)
	if successCount < *repetitions {
		os.Exit(1)
	}
}
