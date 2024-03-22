// Groth16 prover CLI

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
)

// Groth16 proof data
type Groth16Proof struct {
	Proof  []string `json:"proof"`
	Inputs []string `json:"inputs"`
}

// Main entry point
func main() {
	// Parse the CLI arguments.
	inDir := flag.String("in-dir", "", "Input wrapped proof dir path")
	outProof := flag.String("out-proof", "", "Output Groth16 proof file path")
	outContract := flag.String("out-contract", "", "Output Solidity contract file path")
	profileCircuit := flag.Bool("profile", false, "Profile the circuit")
	dummySetup := flag.Bool("dummy", false, "Use the dummy setup")

	flag.Parse()

	fmt.Print("Running Groth16 prover\n")
	fmt.Printf("InDir: %s, OutProof: %s, OutContract: %s\n", *inDir, *outProof, *outContract)
	fmt.Printf("ProfileCircuit: %t, DummySetup: %t\n", *profileCircuit, *dummySetup)

	// Run the prover.
	runProver(*inDir, *outProof, *outContract, *profileCircuit, *dummySetup)
}

// Run the Groth16 prover.
func runProver(inDir string, outProof string, outContract string, profileCircuit bool, dummySetup bool) {
	// Build the circuit.
	r1cs := buildCircuit(inDir, profileCircuit)

	// Generate the proof.
	proof, witness := generateProof(inDir, dummySetup, outContract, r1cs)

	// Save the proof to a file.
	writeProof(outProof, proof, witness)
}

// Build the input circuit, and return an instance of constraint system.
func buildCircuit(inDir string, profileCircuit bool) constraint.ConstraintSystem {
	// Read the circuit data and wrapped proof from the input dir.
	commonCircuitData := types.ReadCommonCircuitData(inDir + "/common_circuit_data.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(inDir + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(inDir + "/verifier_only_circuit_data.json"))

	// Create the verifier circuit.
	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	if profileCircuit {
		p = profile.Start()
	}

	var builder frontend.NewBuilder
	builder = r1cs.NewBuilder

	// Compile the input circuit to CS.
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if profileCircuit {
		// Print the profile result.
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	return r1cs
}

// Generate the Groth16 proof, and return the proof and witness.
func generateProof(inDir string, dummySetup bool, outContract string, r1cs constraint.ConstraintSystem) (groth16.Proof, witness.Witness) {
	// Read the wrapped proof from the input dir.
	// TODO: these data cannot be copied.
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(inDir + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(inDir + "/verifier_only_circuit_data.json"))

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	// Run trusted setup.
	fmt.Println("Running circuit setup", time.Now())
	if dummySetup {
		fmt.Println("Using dummy setup")
		pk, err = groth16.DummySetup(r1cs)
	} else {
		fmt.Println("Using real setup")
		pk, vk, err = groth16.Setup(r1cs)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if outContract != "" {
		// Output the Solidity contract.
		fSolidity, _ := os.Create(outContract)
		err = vk.ExportSolidity(fSolidity)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return proof, witness
}

// Save the proof to a file.
func writeProof(outProof string, proof groth16.Proof, witness witness.Witness) {
	// Both proof and witness will be encoded as U256 (32-bytes).
	const fpSize = 4 * 8

	// Format the proof as 8-U256.
	buf := new(bytes.Buffer)
	proof.WriteRawTo(buf)
	proofBytes := buf.Bytes()
	proofs := make([]string, 8)
	for i := 0; i < 8; i++ {
		proofs[i] = "0x" + hex.EncodeToString(proofBytes[i*fpSize:(i+1)*fpSize])
	}

	// Format the public inputs.
	publicWitness, _ := witness.Public()
	publicWitnessBytes, _ := publicWitness.MarshalBinary()
	// We cut off the first 12 bytes because they encode length information.
	publicWitnessBytes = publicWitnessBytes[12:]
	nbInputs := len(publicWitnessBytes) / fpSize
	inputs := make([]string, nbInputs)
	for i := 0; i < nbInputs; i++ {
		inputs[i] = "0x" + hex.EncodeToString(publicWitnessBytes[i*fpSize:(i+1)*fpSize])
	}

	// Create the output proof data.
	proofData := Groth16Proof{
		Proof:  proofs,
		Inputs: inputs,
	}

	// Format to JSON.
	jsonData, err := json.MarshalIndent(proofData, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling to JSON:", err)
		return
	}

	// Write the proof to a file.
	err = os.WriteFile(outProof, jsonData, 0644)
	if err != nil {
		fmt.Println("Error writing to file:", err)
	}
}
