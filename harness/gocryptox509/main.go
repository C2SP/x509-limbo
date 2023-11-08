package main

//go:generate go run github.com/atombender/go-jsonschema@latest -v -p main -o schema.go ../../limbo-schema.json

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

type testcaseResult string

const (
	validationKindClient = "CLIENT"
	validationKindServer = "SERVER"

	testcaseFailed  testcaseResult = "FAILURE"
	testcasePassed  testcaseResult = "SUCCESS"
	testcaseSkipped testcaseResult = "SKIPPED"
)

func (r testcaseResult) String() string {
	s := map[testcaseResult]string{testcaseFailed: "FAIL", testcasePassed: "PASS", testcaseSkipped: "SKIP"}
	return s[r]
}

type result struct {
	ID      string         `json:"id"`
	Result  testcaseResult `json:"actual_result"`
	Context string         `json:"context"`
}

type results struct {
	Version uint     `json:"version"`
	Harness string   `json:"harness"`
	Results []result `json:"results"`
}

func main() {
	testCasePath := flag.String("testcases", "../../limbo.json", "testcases")
	resultsPath := flag.String("results", "./results.json", "results")
	flag.Parse()

	testcases, err := loadTestcases(*testCasePath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded testcases from %s\n", *testCasePath)

	resultsFile, err := os.Create(*resultsPath)
	if err != nil {
		panic(err)
	}
	resultsEncoder := json.NewEncoder(resultsFile)

	var (
		pass, fail, skip int
		outputResults    results
	)
	for _, tc := range testcases.Testcases {
		fmt.Printf("Running test %s ... ", tc.Id)
		r, err := evaluateTestcase(tc)
		fmt.Printf("%s\n", r)

		var context string
		switch r {
		case testcaseFailed:
			fmt.Printf("%s\nerr=%+#v\n", tc.Description, err)
			context = err.Error()
			fail++
		case testcasePassed:
			pass++
		case testcaseSkipped:
			skip++
			continue
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

	fmt.Printf("done! passed/failed/skipped/total %d/%d/%d/%d.\n", pass, fail, skip, len(testcases.Testcases))
}

func loadTestcases(path string) (testcases Limbo, err error) {
	contents, err := ioutil.ReadFile(path)
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

func evaluateTestcase(testcase Testcase) (testcaseResult, error) {
	_ = spew.Dump

	var ts time.Time
	if testcase.ValidationTime == nil {
		ts = time.Now()
	} else {
		var err error
		ts, err = time.Parse(time.RFC3339, testcase.ValidationTime.(string))

		if err != nil {
			fmt.Printf("%s\n", err)
			return testcaseSkipped, errors.Wrap(err, "unable to parse testcase time as RFC3339")
		}
	}

	expectSuccess := testcaseResult(testcase.ExpectedResult.(string)) == testcasePassed

	// TODO: Support testcases that constrain signature algorthms.
	if testcase.SignatureAlgorithms != nil {
		var signatureAlgorithms []SignatureAlgorithm = testcase.SignatureAlgorithms.([]SignatureAlgorithm)
		if len(signatureAlgorithms) != 0 {
			return testcaseSkipped, fmt.Errorf("signature algorithm checks not supported yet")
		}
	}

	// TODO: Support testcases that constrain key usages.
	if testcase.KeyUsage != nil {
		var keyUsage []interface{} = testcase.KeyUsage.([]interface{})
		if len(keyUsage) != 0 {
			return testcaseSkipped, fmt.Errorf("key usage checks not supported yet")
		}
	}

	var ekus []x509.ExtKeyUsage
	if testcase.ExtendedKeyUsage != nil {
		var extendedKeyUsage []interface{} = testcase.ExtendedKeyUsage.([]interface{})
		extKeyUsagesMap := map[KnownEKUs]x509.ExtKeyUsage{
			KnownEKUsAnyExtendedKeyUsage: x509.ExtKeyUsageAny,
			KnownEKUsClientAuth:          x509.ExtKeyUsageClientAuth,
			KnownEKUsCodeSigning:         x509.ExtKeyUsageCodeSigning,
			KnownEKUsEmailProtection:     x509.ExtKeyUsageEmailProtection,
			KnownEKUsOCSPSigning:         x509.ExtKeyUsageOCSPSigning,
			KnownEKUsServerAuth:          x509.ExtKeyUsageServerAuth,
			KnownEKUsTimeStamping:        x509.ExtKeyUsageTimeStamping,
		}

		for _, elem := range extendedKeyUsage {
			var ekuString = elem.(string)
			expected_eku := KnownEKUs(ekuString)
			ekus = append(ekus, extKeyUsagesMap[expected_eku])
		}
	}

	switch testcase.ValidationKind {
	case validationKindClient:
		return testcaseSkipped, fmt.Errorf("unimplemented validationKindClient")
	case validationKindServer:
		var dnsName string
		if peerName, ok := testcase.ExpectedPeerName.(map[string]interface{}); ok {
			if peerName["kind"] != "DNS" {
				return testcaseSkipped, fmt.Errorf("non-DNS peer name checks not supported yet")
			}
			dnsName = peerName["value"].(string)
		}
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AppendCertsFromPEM(concatPEMCerts(testcase.TrustedCerts))
		intermediates.AppendCertsFromPEM(concatPEMCerts(testcase.UntrustedIntermediates))

		peerAsPEM, rest := pem.Decode([]byte(testcase.PeerCertificate))
		if peerAsPEM == nil || peerAsPEM.Type != "CERTIFICATE" {
			return testcaseFailed, fmt.Errorf("unexpected data, expected cert: %+#v", *peerAsPEM)
		} else if len(rest) > 0 {
			return testcaseFailed, fmt.Errorf("peer certificate has %d trailing bytes", len(rest))
		}

		peer, err := x509.ParseCertificate(peerAsPEM.Bytes)
		if err != nil {
			err = errors.Wrap(err, "unable to parse ASN1 certificate from PEM")
			if expectSuccess {
				return testcaseFailed, err
			} else {
				return testcasePassed, err
			}
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

		if err != nil && expectSuccess {
			return testcaseFailed, errors.Wrap(err, "validation failed when success was expected")
		} else if err == nil && !expectSuccess {
			return testcaseFailed, fmt.Errorf("validation succeeded when failure was expected")
		}
	}

	return testcasePassed, nil
}
