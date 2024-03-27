package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/justpolidor/opa-external-data/data"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	timeout    = 3 * time.Second
	apiVersion = "externaldata.gatekeeper.sh/v1beta1"
)

func main() {
	certFile := "/etc/tls/tls.crt"
	keyFile := "/etc/tls/tls.key"

	caCert, err := os.ReadFile("/tmp/gatekeeper/ca.crt")
	if err != nil {
		panic(err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(caCert)

	if !clientCAs.AppendCertsFromPEM(caCert) {
		log.Fatalf("Failed to append Gatekeeper's CA certificate")
	}

	// Configure TLS settings
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS13,
	}

	server := &http.Server{
		Addr:      ":9443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/validate", validateHandler)

	log.Printf("Starting HTTPS server on %s...", server.Addr)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("Failed to listen and serve: %v", err)
	}
}

func validateHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var providerRequest externaldata.ProviderRequest
	if err := json.NewDecoder(req.Body).Decode(&providerRequest); err != nil {
		http.Error(w, fmt.Sprintf("Unable to unmarshal request body: %v", err), http.StatusBadRequest)
		return
	}

	results, err := processAttestations(req.Context(), providerRequest.Request.Keys)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error processing attestations: %v", err), http.StatusInternalServerError)
		return
	}

	sendResponse(results, "", w)
}

func processAttestations(ctx context.Context, keys []string) ([]externaldata.Item, error) {
	results := []externaldata.Item{}
	verifier, err := loadPublicKeyVerifier()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		ref, err := name.ParseReference(key)
		if err != nil {
			return appendError(results, key, fmt.Sprintf("Error parsing reference: %v", err))
		}

		attestations, err := cosign.FetchAttestationsForReference(ctx, ref)
		if err != nil {
			return appendError(results, key, fmt.Sprintf("Failed to fetch attestations: %v", err))
		}

		for _, attestation := range attestations {
			if err := verifyDSSEEnvelope(ctx, verifier, attestation); err != nil {
				return appendError(results, key, fmt.Sprintf("Failed to verify DSSE: %v", err))
			}
			// After DSSE verification, check for critical vulnerabilities
			if hasCritical, critVulns := checkCriticalVulnerabilities(attestation); hasCritical {
				results = append(results, externaldata.Item{Key: key, Error: fmt.Sprintf("Found critical vulnerabilities: %v", critVulns)})
			} else {
				results = append(results, externaldata.Item{Key: key, Value: key + "_valid"})
			}
		}
	}
	return results, nil
}

func checkCriticalVulnerabilities(attestation cosign.AttestationPayload) (bool, []string) {
	decodedPayload, err := base64.StdEncoding.DecodeString(attestation.PayLoad)
	if err != nil {
		log.Printf("Error decoding base64 payload: %v", err)
		return false, nil
	}

	var payload data.AttestationPayload
	if err = json.Unmarshal(decodedPayload, &payload); err != nil {
		log.Printf("Error unmarshalling JSON payload: %v", err)
		return false, nil
	}

	var criticalVulns []string
	for _, result := range payload.Predicate.Scanner.Result.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if vulnerability.Severity == "CRITICAL" {
				criticalVulns = append(criticalVulns, vulnerability.VulnerabilityID)
			}
		}
	}

	return len(criticalVulns) > 0, criticalVulns
}

func loadPublicKeyVerifier() (signature.Verifier, error) {
	pubKeyBytes, err := os.ReadFile("/etc/cosign/cosign.pub")
	if err != nil {
		return nil, fmt.Errorf("error reading public key file: %v", err)
	}

	block, _ := pem.Decode(pubKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key: %v", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not of type ECDSA")
	}

	return signature.LoadECDSAVerifier(ecdsaPubKey, crypto.SHA256)
}

func convertCosignSignatures(cosignSigs []cosign.Signatures) []ssldsse.Signature {
	var ssldsseSigs []ssldsse.Signature
	for _, cosignSig := range cosignSigs {
		ssldsseSig := ssldsse.Signature{
			KeyID: cosignSig.KeyID,
			Sig:   cosignSig.Sig,
		}
		ssldsseSigs = append(ssldsseSigs, ssldsseSig)
	}
	return ssldsseSigs
}

func verifyDSSEEnvelope(ctx context.Context, verifier signature.Verifier, attestation cosign.AttestationPayload) error {
	dsseEnvelope := ssldsse.Envelope{
		PayloadType: types.IntotoPayloadType,
		Payload:     attestation.PayLoad,
		Signatures:  convertCosignSignatures(attestation.Signatures),
	}

	envelopeBytes, err := json.Marshal(dsseEnvelope)
	if err != nil {
		return fmt.Errorf("failed to marshal DSSE envelope: %v", err)
	}

	env := ssldsse.Envelope{}
	if err := json.Unmarshal(envelopeBytes, &env); err != nil {
		return fmt.Errorf("failed to unmarshal DSSE envelope: %v", err)
	}

	dssev, err := ssldsse.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: verifier})
	if err != nil {
		return fmt.Errorf("failed to create DSSE envelope verifier: %v", err)
	}

	_, err = dssev.Verify(ctx, &env)
	return err // This will return nil if verification is successful or an error if it fails
}

func appendError(results []externaldata.Item, key, errorMsg string) ([]externaldata.Item, error) {
	results = append(results, externaldata.Item{
		Key:   key,
		Error: errorMsg,
	})
	return results, fmt.Errorf(errorMsg)
}

func appendValid(results []externaldata.Item, key string, attestation cosign.AttestationPayload) []externaldata.Item {
	// Here you can further process the attestation payload if needed
	results = append(results, externaldata.Item{
		Key:   key,
		Value: key + "_valid", // or any other appropriate value
	})
	return results
}

func sendResponse(results []externaldata.Item, systemErr string, w http.ResponseWriter) {
	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
	}

	if len(results) > 0 {
		response.Response.Items = results
	} else {
		response.Response.SystemError = systemErr
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func getEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s not set", key)
	}
	return value
}
