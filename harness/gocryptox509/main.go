package main

//go:generate go run github.com/atombender/go-jsonschema/cmd/gojsonschema@latest -v -p main -o schema.go ../../limbo-schema.json

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

type testcaseResult uint

const (
	testcaseFailed testcaseResult = iota
	testcasePassed
	testcaseSkipped
)

func (r testcaseResult) String() string {
	s := map[testcaseResult]string{testcaseFailed: "FAIL", testcasePassed: "PASS", testcaseSkipped: "SKIP"}
	return s[r]
}

func main() {
	testCasePath := flag.String("testcases", "../../limbo.json", "testcases")
	flag.Parse()

	testcases, err := loadTestcases(*testCasePath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded testcases from %s\n", *testCasePath)

	var pass, fail, skip int
	for _, tc := range testcases.Testcases {
		fmt.Printf("Running test %s ... ", tc.Id)
		result, err := evaluateTestcase(tc)
		fmt.Printf("%s\n", result)
		switch result {
		case testcaseFailed:
			fmt.Printf("%s\nerr=%+#v\n", tc.Description, err)
			fail++
		case testcasePassed:
			pass++
		case testcaseSkipped:
			skip++
		}
	}

	fmt.Printf("done! passed/failed/skipped/total %d/%d/%d/%d.\n", pass, fail, skip, len(testcases.Testcases))
}

func loadTestcases(path string) (testcases LimboSchemaJson, err error) {
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

const (
	validationKindClient = "CLIENT"
	validationKindServer = "SERVER"

	resultSuccess = "SUCCESS"
	resultFailure = "FAILURE"
)

func evaluateTestcase(testcase Testcase) (testcaseResult, error) {
	_ = spew.Dump

	var ts time.Time
	if testcase.ValidationTime == nil {
		ts = time.Now()
	} else {
		var err error
		ts, err = time.Parse(time.RFC3339, *testcase.ValidationTime)

		if err != nil {
			return testcaseSkipped, errors.Wrap(err, "unable to parse testcase time as RFC3339")
		}
	}

	expectSuccess := testcase.ExpectedResult == resultSuccess

	// TODO: Support testcases that constrain signature algorthms.
	if len(testcase.SignatureAlgorithms) != 0 {
		return testcaseSkipped, fmt.Errorf("signature algorithm checks not supported yet")
	}

	// TODO: Support testcases that constrain key usages.
	if len(testcase.KeyUsage) != 0 {
		return testcaseSkipped, fmt.Errorf("key usage checks not supported yet")
	}

	// TODO: Support testcases that constrain extended key usages.
	if len(testcase.ExtendedKeyUsage) != 0 {
		return testcaseSkipped, fmt.Errorf("extended key usage checks not supported yet")
	}

	switch testcase.ValidationKind {
	case validationKindClient:
		var dnsName string
		if peerName, ok := testcase.ExpectedPeerName.(PeerName); ok {
			if peerName.Kind.(string) != "DNS" {
				return testcaseSkipped, fmt.Errorf("non-DNS peer name checks not supported yet")
			}
			dnsName = peerName.Value
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
			KeyUsages:     nil,
		}
		chain, err := peer.Verify(opts)
		_ = chain

		if err != nil && expectSuccess {
			return testcaseFailed, errors.Wrap(err, "validation failed when success was expected")
		} else if err == nil && !expectSuccess {
			return testcaseFailed, fmt.Errorf("validation succeeded when failure was expected")
		}
	case validationKindServer:
		return testcaseSkipped, fmt.Errorf("unimplemented validationKindServer")
	}

	return testcasePassed, nil
}
