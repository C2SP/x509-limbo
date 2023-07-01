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
	"os"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

func main() {
	testCasePath := flag.String("testcases", "../../limbo.json", "testcases")
	flag.Parse()

	testcases, err := loadTestcases(*testCasePath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded testcases from %s\n", *testCasePath)

	var success, fail int
	for _, tc := range testcases.Testcases {
		fmt.Printf("test id=%s ... ", tc.Id)
		if err := evaluateTestcase(tc); err != nil {
			fmt.Printf("fail\n\n%+#v\n\nTest description:\n\n%s\n", err, tc.Description)
			fail++
		} else {
			fmt.Printf("ok\n")
			success++
		}
	}

	fmt.Printf("done! succeeded/failed/total %d/%d/%d.\n", success, fail, len(testcases.Testcases))
	if fail > 0 {
		os.Exit(1)
	}
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

func evaluateTestcase(testcase Testcase) error {
	_ = spew.Dump

	var ts time.Time
	if testcase.ValidationTime == nil {
		ts = time.Now()
	} else {
		var err error
		ts, err = time.Parse(time.RFC3339, *testcase.ValidationTime)

		if err != nil {
			return errors.Wrap(err, "unable to parse testcase time as RFC3339")
		}
	}

	expectSuccess := testcase.ExpectedResult == resultSuccess

	// TODO: Support testcases that constrain signature algorthms.
	if len(testcase.SignatureAlgorithms) != 0 {
		return fmt.Errorf("signature algorithm checks not supported yet")
	}

	// TODO: Support testcases that constrain key usages.
	if len(testcase.KeyUsage) != 0 {
		return fmt.Errorf("key usage checks not supported yet")
	}

	// TODO: Support testcases that constrain extended key usages.
	if len(testcase.ExtendedKeyUsage) != 0 {
		return fmt.Errorf("extended key usage checks not supported yet")
	}

	switch testcase.ValidationKind {
	case validationKindClient:
		// TODO: Support testcases that specify the peer's name.
		if testcase.ExpectedPeerName != nil {
			return fmt.Errorf("peer name checks not supported yet")
		}
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AppendCertsFromPEM(concatPEMCerts(testcase.TrustedCerts))
		intermediates.AppendCertsFromPEM(concatPEMCerts(testcase.UntrustedIntermediates))

		peerAsPEM, rest := pem.Decode([]byte(testcase.PeerCertificate))
		if peerAsPEM == nil || peerAsPEM.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected data, expected cert: %+#v", *peerAsPEM)
		} else if len(rest) > 0 {
			return fmt.Errorf("peer certificate has %d trailing bytes", len(rest))
		}

		peer, err := x509.ParseCertificate(peerAsPEM.Bytes)
		if err != nil {
			return errors.Wrap(err, "unable to parse ASN1 certificate from PEM")
		}

		opts := x509.VerifyOptions{
			Intermediates: intermediates,
			Roots:         roots,
			CurrentTime:   ts,
			KeyUsages:     nil,
		}
		chain, err := peer.Verify(opts)
		_ = chain

		if err != nil && expectSuccess {
			return errors.Wrap(err, "validation failed when success was expected")
		} else if err == nil && !expectSuccess {
			return fmt.Errorf("validation succeeded when failure was expected")
		}
	case validationKindServer:
		return fmt.Errorf("unimplemented validationKindServer")
	}

	return nil
}
