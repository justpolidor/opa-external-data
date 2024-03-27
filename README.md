# OPA EXTERNAL DATA

## Overview

This README provides an overview and guidance on setting up an admission control mechanism in a Kubernetes cluster using OPA Gatekeeper and the external-data feature. The use case is to check for [VULN attestations](https://github.com/in-toto/attestation/blob/main/spec/predicates/vuln.md) attested to the OCI images being deployed in the Kubernetes cluster. If any CRITICAL vulnerability is present, then Gatekeeper will reject the deployment.

TBD