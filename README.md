# OPA EXTERNAL DATA

## Overview

This README provides an overview and guidance on setting up an admission control mechanism in a Kubernetes cluster using OPA Gatekeeper and the external-data feature. The use case is to check for [VULN attestations](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md) attested to the OCI images being deployed in the Kubernetes cluster. If any CRITICAL vulnerability is present, then Gatekeeper will reject the deployment.

## PoC Description
This application sets up an HTTPS server that can be queried by Gatekeeper to validate Docker images based on their security posture before allowing them into the Kubernetes cluster. It's a crucial tool aimed at preventing the deployment of images that contain critical vulnerabilities, thus maintaining a high security standard.

## Main Components

### `main` function
- **Description**: Initializes the HTTPS server with different configurations based on the environment (local or production).
- **Details**:
  - **Local Environment**: Starts an HTTP server on port 8443 for development and testing.
  - **Production Environment**: Configures TLS settings, including client certificate verification, and runs the server on port 9443 to ensure secure communications within the cluster.

### `validateHandler` function
- **Description**: This is the HTTP endpoint handler that processes POST requests. It extracts Docker image keys from the requests and passes them to `processAttestations` for security checks.
- **Details**: It decodes incoming JSON data into a `ProviderRequest`, ensuring that only POST methods are used. Errors in request processing or attestation handling are directly communicated back to the requester.

### `processAttestations` function
- **Core of the PoC**: Verifies the integrity and authenticity of image attestations and checks them for critical vulnerabilities.
- **Details**:
  - **Verification Step**: Uses `cosign` library functions to verify digital signatures and claims in the image attestations against a public key.
  - **Vulnerability Check**: After verification, it fetches specific vulnerability attestations and checks for any listed as "CRITICAL". This step determines whether an image is compliant or if it poses a security risk.

### `checkCriticalVulnerabilities` function
- **Description**: Analyzes attestation payloads to identify critical vulnerabilities.
- **Details**: Decodes the base64-encoded payload from the attestation, parses it into a structured JSON format, and scans for vulnerabilities tagged as "CRITICAL" in the severity field.

### `loadPublicKeyVerifier` function
- **Description**: Prepares a signature verifier using a public key that will be used to authenticate the attestation signatures.
- **Details**: Reads and decodes a PEM-formatted public key, converting it into a verifier object that can be used by the `cosign` library.

### `appendError` and `sendResponse` functions
- **Utility Functions**:
  - **`appendError`**: Adds an error entry to the results, documenting any issues encountered during image processing.
  - **`sendResponse`**: Formats and sends the validation results back to Gatekeeper, using either the list of processed results or reporting a system error.

## Usage
To use this PoC in a Kubernetes environment:
1. Install and configure OPA Gatekeeper to utilize external data providers.
2. Deploy this application within the cluster and set up Gatekeeper to query this service for validating image deployments.
3. Ensure TLS configurations and client certificate verifications are in place for secure communication.