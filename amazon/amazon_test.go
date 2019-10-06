package amazon

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/xerrors"

	"github.com/stretchr/testify/assert"
)

func Test_Update(t *testing.T) {
	testCases := []struct {
		name          string
		xmlResponse   string
		gzipFileName  string
		expectedError error
	}{
		{
			name:          "happy path",
			xmlResponse:   goodRepoMDXMLResponse,
			gzipFileName:  "test-data/updateinfo.xml.gz.valid",
			expectedError: nil,
		},
		{
			name: "bad XML response",
			xmlResponse: `<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
</repomd>`,
			expectedError: xerrors.Errorf("failed to update security advisories of Amazon Linux %s: %w", "1", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
		{
			name:          "bad gzip data response",
			xmlResponse:   goodRepoMDXMLResponse,
			gzipFileName:  "this is some bad gzip data",
			expectedError: xerrors.Errorf("failed to update security advisories of Amazon Linux %s: %w", "1", errors.New("failed to fetch security advisories from Amazon Linux Security Center: Failed to fetch updateinfo")),
		},
	}

	for _, tc := range testCases {

		tsUpdateInfoURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "repomd.xml"):
				_, _ = fmt.Fprintln(w, tc.xmlResponse)
			case strings.Contains(r.URL.Path, "updateinfo.xml.gz"):
				buf, _ := ioutil.ReadFile(tc.gzipFileName)
				_, _ = w.Write(buf)
			default:
				assert.Fail(t, "bad URL requested: ", r.URL.Path, tc.name)
			}
		}))
		defer tsUpdateInfoURL.Close()

		tsMirrorListURL := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintln(w, tsUpdateInfoURL.URL)
		}))
		defer tsMirrorListURL.Close()

		ac := Config{
			LinuxMirrorListURI: map[string]string{
				"1": tsMirrorListURL.URL,
				"2": tsMirrorListURL.URL,
			}}

		switch {
		case tc.expectedError != nil:
			assert.Equal(t, tc.expectedError.Error(), ac.Update().Error(), tc.name)
		default:
			assert.NoError(t, ac.Update(), tc.name)
		}
	}
}

var goodRepoMDXMLResponse = `<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
 <revision>1569885898</revision>
<data type="primary_db">
  <checksum type="sha256">b35d5ddbb9e1c80b2f0bfec2f6a4c3899f3fd701e9b967e822b5c9b74c623a21</checksum>
  <open-checksum type="sha256">da73ee6f76309be935cbc3494df6a8bfd038ff400da446617f413e6420e70107</open-checksum>
  <location href="repodata/primary.sqlite.bz2"/>
  <timestamp>1569885887</timestamp>
  <database_version>10</database_version>
  <size>2336884</size>
  <open-size>11857920</open-size>
</data>
<data type="other_db">
  <checksum type="sha256">452881918b03215900f70e2c90e4eb1533cf71e1f1013c1df9681dd886dc14f7</checksum>
  <open-checksum type="sha256">5f162ee4f4fd0d682e1935e2889c4f47dec47dca07f3f0ba712f234775cbeae8</open-checksum>
  <location href="repodata/other.sqlite.bz2"/>
  <timestamp>1569885898</timestamp>
  <database_version>10</database_version>
  <size>475</size>
  <open-size>24576</open-size>
</data>
<data type="group_gz">
  <checksum type="sha256">3fac89ebf98a0454ec2c5762bee860ca89097cb5cbcdab58f475ea7534fe33f8</checksum>
  <open-checksum type="sha256">15e8cea4bf15229236bc5641a33ca273b3661d09a31a8b1092c15d4e6ba8b89e</open-checksum>
  <location href="repodata/comps.xml.gz"/>
  <timestamp>1569885884</timestamp>
  <database_version>10</database_version>
  <size>4459</size>
  <open-size>34460</open-size>
</data>
<data type="group">
  <checksum type="sha256">15e8cea4bf15229236bc5641a33ca273b3661d09a31a8b1092c15d4e6ba8b89e</checksum>
  <location href="repodata/comps.xml"/>
  <timestamp>1569885884</timestamp>
  <database_version>10</database_version>
  <size>34460</size>
</data>
<data type="filelists_db">
  <checksum type="sha256">57dda689463e901cf78f9c0f7e6ae0deb54e1211a7291c3c1bc7dec2567a8864</checksum>
  <open-checksum type="sha256">c6baae49573338c9d3bcec48b899a3e373ec80fa3c30598c69acf565e3e93ad0</open-checksum>
  <location href="repodata/filelists.sqlite.bz2"/>
  <timestamp>1569885898</timestamp>
  <database_version>10</database_version>
  <size>11394011</size>
  <open-size>65867776</open-size>
</data>
<data type="updateinfo">
  <checksum type="sha256">109fc2fc31f6576789171b9854916898b05a42fda4c888ff766e7328598a8898</checksum>
  <open-checksum type="sha256">91498cad8c8dc166bf506119772acae5f4d722b4759a5126c0d0b9d99c350ac1</open-checksum>
  <location href="repodata/updateinfo.xml.gz"/>
  <timestamp>1569885884</timestamp>
  <database_version>10</database_version>
  <size>614760</size>
  <open-size>6438792</open-size>
</data>
</repomd>`
