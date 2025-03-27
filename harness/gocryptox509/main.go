package main

//go:generate go run github.com/atombender/go-jsonschema@v0.17.0 -v -p main -o schema.go ../../limbo-schema.json

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

type actualResult string

const (
	resultFailure actualResult = "FAILURE"
	resultSuccess actualResult = "SUCCESS"
	resultSkipped actualResult = "SKIPPED"
)

type result struct {
	ID      string       `json:"id"`
	Result  actualResult `json:"actual_result"`
	Context string       `json:"context"`
}

type results struct {
	Version uint     `json:"version"`
	Harness string   `json:"harness"`
	Results []result `json:"results"`
}

func main() {
	testcases, err := loadTestcases()
	if err != nil {
		panic(err)
	}

	resultsEncoder := json.NewEncoder(os.Stdout)

	var (
		conform, nonconform, skip int
		outputResults             results
	)
	for _, tc := range testcases.Testcases {
		fmt.Fprintf(os.Stderr, "Running test %s ... ", tc.Id)
		r, err := evaluateTestcase(tc)

		var context string
		if string(r) != string(tc.ExpectedResult) {
			if r != resultSkipped {
				fmt.Fprintf(os.Stderr, "NON-CONFORMANT\n\terr=%s\n", err)
				nonconform++
			} else {
				fmt.Fprintln(os.Stderr, "SKIPPED")
				skip++
			}

			if err != nil {
				context = err.Error()
			}
		} else {
			fmt.Fprintln(os.Stderr, "CONFORMANT")
			conform++
		}

		outputResults.Results = append(outputResults.Results, result{
			ID:      tc.Id,
			Context: context,
			Result:  r,
		})
	}

	outputResults.Version = 1
	outputResults.Harness = fmt.Sprintf("gocryptox509-%s", runtime.Version())
	resultsEncoder.Encode(outputResults)

	fmt.Fprintf(os.Stderr, "done! conformant/nonconformant/skipped/total %d/%d/%d/%d.\n", conform, nonconform, skip, len(testcases.Testcases))
}

func loadTestcases() (testcases Limbo, err error) {
	contents, err := io.ReadAll(os.Stdin)
	if err != nil {
		return
	}

	err = json.Unmarshal(contents, &testcases)
	return
}

func concatPEMCerts(certs []string) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.WriteString(cert)
	}
	return buf.Bytes()
}

func evaluateTestcase(testcase Testcase) (actualResult, error) {
	_ = spew.Dump

	for _, feature := range testcase.Features {
		if feature == "max-chain-depth" {
			return resultSkipped, fmt.Errorf("max chain depth not supported")
		}
	}

	var ts time.Time
	if testcase.ValidationTime == nil {
		ts = time.Now()
	} else {
		var err error
		ts, err = time.Parse(time.RFC3339, testcase.ValidationTime.(string))

		if err != nil {
			fmt.Printf("%s\n", err)
			return resultSkipped, errors.Wrap(err, "unable to parse testcase time as RFC3339")
		}
	}

	// TODO: Support testcases that constrain signature algorthms.
	var signatureAlgorithms = testcase.SignatureAlgorithms
	if len(signatureAlgorithms) != 0 {
		return resultSkipped, fmt.Errorf("signature algorithm checks not supported yet")
	}

	// NOTE: We allow a digitialSignature keyUsage, but otherwise don't
	// support anything due to Go's limited support for keyUsage.
	// See: https://github.com/golang/go/issues/40100
	var keyUsages = testcase.KeyUsage
	hasDigitalSignature := slices.ContainsFunc(keyUsages, func(ku KeyUsage) bool {
		return ku == KeyUsageDigitalSignature
	})
	if len(keyUsages) != 0 && !hasDigitalSignature {
		return resultSkipped, fmt.Errorf("key usage checks not supported yet")
	}

	if testcase.MaxChainDepth != nil {
		return resultSkipped, fmt.Errorf("max chain depth not supported")
	}

	var ekus []x509.ExtKeyUsage
	if testcase.ExtendedKeyUsage != nil {
		extKeyUsagesMap := map[KnownEKUs]x509.ExtKeyUsage{
			KnownEKUsAnyExtendedKeyUsage: x509.ExtKeyUsageAny,
			KnownEKUsClientAuth:          x509.ExtKeyUsageClientAuth,
			KnownEKUsCodeSigning:         x509.ExtKeyUsageCodeSigning,
			KnownEKUsEmailProtection:     x509.ExtKeyUsageEmailProtection,
			KnownEKUsOCSPSigning:         x509.ExtKeyUsageOCSPSigning,
			KnownEKUsServerAuth:          x509.ExtKeyUsageServerAuth,
			KnownEKUsTimeStamping:        x509.ExtKeyUsageTimeStamping,
		}

		for _, elem := range testcase.ExtendedKeyUsage {
			expected_eku := KnownEKUs(elem)
			ekus = append(ekus, extKeyUsagesMap[expected_eku])
		}
	}

	switch testcase.ValidationKind {
	case ValidationKindCLIENT:
		return resultSkipped, fmt.Errorf("unimplemented validationKindClient")
	case ValidationKindSERVER:
		var dnsName string
		if peerName, ok := testcase.ExpectedPeerName.(map[string]interface{}); ok {
			if peerName["kind"] == "DNS" {
				dnsName = peerName["value"].(string)
			} else {
				// crypto/x509 takes IP subjects in `[addr]` form.
				dnsName = fmt.Sprintf("[%s]", peerName["value"].(string))
			}
		}
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AppendCertsFromPEM(concatPEMCerts(testcase.TrustedCerts))
		intermediates.AppendCertsFromPEM(concatPEMCerts(testcase.UntrustedIntermediates))

		peerAsPEM, rest := pem.Decode([]byte(testcase.PeerCertificate))
		if peerAsPEM == nil || peerAsPEM.Type != "CERTIFICATE" {
			return resultFailure, fmt.Errorf("unexpected data, expected cert: %+#v", *peerAsPEM)
		} else if len(rest) > 0 {
			return resultFailure, fmt.Errorf("peer certificate has %d trailing bytes", len(rest))
		}

		peer, err := x509.ParseCertificate(peerAsPEM.Bytes)
		if err != nil {
			err = errors.Wrap(err, "unable to parse ASN1 certificate from PEM")
			return resultFailure, err
		}

		opts := x509.VerifyOptions{
			DNSName:       dnsName,
			Intermediates: intermediates,
			Roots:         roots,
			CurrentTime:   ts,
			KeyUsages:     ekus,
		}
		chain, err := peer.Verify(opts)
		_ = chain

		var (
			expected = testcase.ExpectedResult
			actual   actualResult
		)
		if err != nil {
			actual = resultFailure
		} else {
			actual = resultSuccess
		}

		if string(expected) != string(actual) {
			if err == nil {
				err = errors.New("chain built")
			}
			err = errors.Wrap(err, "validation")
		}
		return actual, err
	}

	return resultSkipped, errors.New("no result returned from evaulation")
}
