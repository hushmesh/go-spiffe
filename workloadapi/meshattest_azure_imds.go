package workloadapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// imdsTDQuoteURL is IMDS_QUOTE_URL in mesh-process
// crates/crate-app-azure-vtpm-tdx/src/imds.rs. The Azure Instance Metadata Service answers on a
// link-local address that is never routed off the host and speaks plain HTTP; there is nothing to
// authenticate and nothing to configure, so the address is a constant rather than an option.
const imdsTDQuoteURL = "http://169.254.169.254/acc/tdquote"

// imdsTDQuoteEndpoint is the address the collector actually posts to. It is a variable solely so a
// test can point it at an httptest server; nothing outside a test writes it.
var imdsTDQuoteEndpoint = imdsTDQuoteURL

// A quote is signed by the platform's quoting enclave, not by IMDS, so this is bounded well above
// a normal round trip and only fires for a service that has stopped answering. The response is a
// single base64 quote of a few kilobytes, so a body far past that is a wrong endpoint rather than
// a large quote.
const (
	imdsTimeout          = 30 * time.Second
	imdsMaxResponseBytes = 1 << 20
)

// Proxy: nil, deliberately. http.DefaultClient honours HTTP_PROXY/ALL_PROXY and does not exempt
// link-local addresses, so anything able to set this process's environment could redirect the TD
// report to a host of its choosing. A metadata endpoint is never reached through a proxy.
var imdsClient = &http.Client{Transport: &http.Transport{Proxy: nil}}

type imdsReportBody struct {
	Report string `json:"report"`
}

type imdsQuoteResponse struct {
	Quote string `json:"quote"`
}

// fetchTDQuote exchanges a TD report for a TDX quote over it. The report goes up and the quote
// comes back as unpadded base64url, which is what the Rust's base64-url crate emits and accepts.
func fetchTDQuote(ctx context.Context, tdReport []byte) ([]byte, error) {
	body, err := json.Marshal(imdsReportBody{Report: base64.RawURLEncoding.EncodeToString(tdReport)})
	if err != nil {
		return nil, fmt.Errorf("encoding the td report for IMDS failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, imdsTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, imdsTDQuoteEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building the IMDS quote request failed: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := imdsClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("asking IMDS at %s for a td quote failed: %w", imdsTDQuoteEndpoint, err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, imdsMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading the IMDS quote response failed: %w", err)
	}
	// IMDS reports a refused report -- a stale one, or one from a machine it does not consider a
	// TD -- as an HTTP status with a body that is not a quote. Naming the status here is the
	// difference between a diagnosable local failure and a quote the mesh rejects for no visible
	// reason.
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS answered the td quote request with HTTP %s: %s", response.Status, strings.TrimSpace(string(payload)))
	}

	var decoded imdsQuoteResponse
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("the IMDS quote response will not decode as JSON: %w", err)
	}
	if decoded.Quote == "" {
		return nil, fmt.Errorf("IMDS answered with no quote field")
	}

	// The Rust decodes with the unpadded alphabet, which rejects padding outright. Tolerating it
	// here cannot misread anything -- the alphabet is the same and '=' carries no bits -- and
	// costs nothing, where a refusal would look like a corrupt quote.
	quote, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(decoded.Quote, "="))
	if err != nil {
		return nil, fmt.Errorf("the quote IMDS returned is not base64url: %w", err)
	}
	if len(quote) == 0 {
		return nil, fmt.Errorf("IMDS answered with an empty quote")
	}
	return quote, nil
}
