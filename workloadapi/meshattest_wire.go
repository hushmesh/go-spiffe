package workloadapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Every value in this file must agree byte-for-byte with the mesh's SPIFFE agent. A mismatch is
// not diagnosable from the wire: the mesh answers one uniform PermissionDenied for every
// request-derived failure (refuse_workload_attestation, mesh-process
// actors/actor-spiffe-agent/src/attestation.rs), so a wrong label looks exactly like a wrong
// measurement. Each constant names its mesh-side definition.
const (
	// getEnvelopeKeyPath is GET_ENVELOPE_KEY_PATH,
	// actors/actor-spiffe-agent/src/workload_attestation_handler.rs. It is never an envelope AAD
	// grpc_path: this route carries no envelope.
	getEnvelopeKeyPath = "/hushmesh.api.server.workload.v1.WorkloadAttestation/GetEnvelopeKey"

	// getAttestationChallengePath is GET_ATTESTATION_CHALLENGE_PATH, same file. It doubles as the
	// envelope AAD's grpc_path.
	getAttestationChallengePath = "/hushmesh.api.server.workload.v1.WorkloadAttestation/GetAttestationChallenge"

	// attestWorkloadPath is ATTEST_WORKLOAD_PATH, same file. It doubles as the envelope AAD's
	// grpc_path.
	attestWorkloadPath = "/hushmesh.api.server.workload.v1.WorkloadAttestation/AttestWorkload"
)

// envelopeSuiteEccP256MlKem768Aes256Gcm is ENVELOPE_SUITE_ECC_P256_MLKEM768_AES256GCM. The wire
// integer is fixed independently of the EnvelopeSuite enum so renumbering the enum cannot
// renumber the wire.
const envelopeSuiteEccP256MlKem768Aes256Gcm = 1

// envelopeSuiteVariantIndex is what the CBOR AAD carries for the same suite. The AAD serializes
// the Rust enum, not the wire integer, and serde_cbor's packed format writes a unit variant as
// its variant index -- so the two differ and both are part of the contract.
const envelopeSuiteVariantIndex = 0

// attestationTypeMeshTdxVtpm is ATTESTATION_TYPE_MESH_TDX_VTPM. It is also sealed into the
// challenge token and re-checked on the attest leg by open_challenge_token.
const attestationTypeMeshTdxVtpm = "mesh_tdx_vtpm"

// The two directional envelope labels, ENVELOPE_LABEL_W2M and ENVELOPE_LABEL_M2W in
// actors/actor-spiffe-agent/src/envelope.rs. Sealing a request under the mesh-to-workload label
// is the reflection the mesh's the_response_key_does_not_open_the_request_leg test asserts is
// refused.
var (
	envelopeLabelW2M = []byte("hushmesh-spiffe-workload-envelope-w2m-v1")
	envelopeLabelM2W = []byte("hushmesh-spiffe-workload-envelope-m2w-v1")
)

// workloadNonceBindingLabel is WORKLOAD_NONCE_BINDING_LABEL,
// actors/actor-spiffe-agent/src/attestation.rs, the first element of the ADR-0041 fold. A change
// to the bound tuple bumps this label rather than reinterpreting the fold.
var workloadNonceBindingLabel = []byte("hushmesh-spiffe-workload-v1")

// envelopeAdvertisementDomain is ENVELOPE_ADVERTISEMENT_DOMAIN,
// actors/actor-spiffe-agent/src/envelope_advertisement_handler.rs. It is hashed with SHA-256 into
// the fold's starting key, not folded in as a step.
var envelopeAdvertisementDomain = []byte("hushmesh-spiffe-envelope-advertisement-v1")

// The two var_data operation discriminants, VAR_DATA_OPERATION_ABSENT and _SHA256 in
// actors/actor-spiffe-agent/src/workload_attestation_handler.rs. Deliberately NOT ReportDataOp's
// own discriminants: 0 on this wire means the field was omitted, so the enum is shifted by one
// and an omitted field stays distinguishable from an explicit no-op.
const (
	varDataOperationAbsent = 0
	varDataOperationSha256 = 2
)

// maxClientRequestIDLen is MAX_CLIENT_REQUEST_ID_LEN, same file. Anything longer is refused
// before it is echoed back.
const maxClientRequestIDLen = 64

// clientRequestIDLen is the size this client actually sends.
const clientRequestIDLen = 16

// meshIDLen is the width of every derived key, nonce and identifier on this wire.
const meshIDLen = 32

// agentServerSPIFFEID is the SAN URI the advertisement leaf must carry, per ADR-0043 Decision 5
// and SPIFFEAgent::generate_agent_server_certificate (actors/actor-spiffe-agent/src/lib.rs),
// which requests format!("spiffe://{}/spire/server", self.fqdn).
func agentServerSPIFFEID(agentFQDN string) string {
	return "spiffe://" + agentFQDN + "/spire/server"
}

// meshDeriveKey is hmc_derive_key (c-libraries/hushmesh-crypto/hm_crypt.c), which is
// hmc_hmac_sign with SHA-256: HMAC-SHA256(key, input).
func meshDeriveKey(key, input []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}

// meshDeriveKeyFromVec is mesh_derive_key_from_vec: each part is its own keyed step, so no byte
// can shift across a part boundary the way it could under a bare concatenation.
func meshDeriveKeyFromVec(key []byte, parts ...[]byte) []byte {
	out := key
	for _, part := range parts {
		out = meshDeriveKey(out, part)
	}
	return out
}

// meshHashToID is mesh_hash_to_id: SHA-256 down to the 32 bytes every mesh identifier is.
func meshHashToID(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

// advertisementSigningInput mirrors advertisement_signing_input,
// actors/actor-spiffe-agent/src/envelope_advertisement_handler.rs.
//
// Five fields, folded in ascending protobuf tag order, each at its own HMAC step: key_id (1),
// ecc_public_key_spki (2), mlkem_public_key (3), big-endian expires_at (4) and trust_domain (7)
// as UTF-8. Ascending tag order is the rule, so a later signed field appends at its own tag
// position rather than at the end of whatever the fold happened to be.
func advertisementSigningInput(keyID, eccPublicKeySPKI, mlkemPublicKey []byte, expiresAt int64, trustDomain string) []byte {
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(expiresAt))
	return meshDeriveKeyFromVec(
		meshHashToID(envelopeAdvertisementDomain),
		keyID,
		eccPublicKeySPKI,
		mlkemPublicKey,
		expiry[:],
		[]byte(trustDomain),
	)
}

// deriveWorkloadAttestationNonce mirrors derive_workload_attestation_nonce,
// actors/actor-spiffe-agent/src/attestation.rs, which is the whole of ADR-0041 Decision 1. The
// 32 bytes that go in ReportData.nonce.
//
// Two byte-exactness obligations survive this function and cannot be checked inside it: csrDER
// must be the DER the issuer will sign over rather than a PEM round trip, and meshEnvelopeECCPub
// must be the advertised bytes verbatim rather than a re-encoding of the same key. Either
// substitution changes the nonce, and the mesh then refuses with no indication of which component
// moved.
func deriveWorkloadAttestationNonce(challengeSeed []byte, workloadUNSName string, meshEnvelopeECCPub, csrDER []byte) ([]byte, error) {
	if len(challengeSeed) != meshIDLen {
		return nil, fmt.Errorf("challenge seed is %d bytes, not %d", len(challengeSeed), meshIDLen)
	}
	return meshDeriveKeyFromVec(
		challengeSeed,
		workloadNonceBindingLabel,
		[]byte(workloadUNSName),
		meshEnvelopeECCPub,
		csrDER,
	), nil
}
