/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parse(t *testing.T) {
	testCases := []struct {
		name     string
		filePath string
		want     *Vulnerability
		wantErr  error
	}{
		{
			name:     "no references or notes",
			filePath: "./testdata/no_references_or_notes",
			want: &Vulnerability{
				Candidate:   "CVE-2020-24241",
				PublicDate:  time.Date(2020, 8, 25, 0, 0, 0, 0, time.UTC),
				Description: "In Netwide Assembler (NASM) 2.15rc10, there is heap use-after-free in saa_wbytes in nasmlib/saa.c.",
				Priority:    "medium",
				Bugs: []string{
					"LINCD-2974",
					"LIN1019-5289",
					"LIN1018-6614",
					"LIN10-7689",
				},
				Patches: map[Package]Statuses{
					Package("nasm"): {
						"10.17.41.1": {
							Status: "released",
							Note:   "10.17.41.22",
						},
						"10.18.44.1": {
							Status: "ignored",
							Note:   "",
						},
						"10.19.45.1": {
							Status: "pending",
							Note:   "",
						},
						"10.20.6.0": {
							Status: "not-affected",
							Note:   "",
						},
					},
				},
			},
		},
		{
			name:     "multiple references and notes",
			filePath: "./testdata/multiple_references_and_notes",
			want: &Vulnerability{
				Candidate:   "CVE-2021-39648",
				PublicDate:  time.Date(2021, 12, 15, 0, 0, 0, 0, time.UTC),
				Description: "In gadget_dev_desc_UDC_show of configfs.c, there is a possible disclosure of kernel heap memory due to a race condition.",
				References: []string{
					"Upstream kernel",
					"Upstream linux",
				},
				Notes: []string{
					"This could lead to local information disclosure with System execution privileges needed.",
					"User interaction is not needed for exploitation.",
				},
				Priority: "medium",
				Bugs: []string{
					"LINCD-7525",
					"LIN1021-2165",
					"LIN1019-7478",
					"LIN1018-8466",
				},
				Patches: map[Package]Statuses{
					Package("linux"): {
						"10.18.44.1": {
							Status: "released",
							Note:   "10.18.44.25",
						},
						"10.19.45.1": {
							Status: "released",
							Note:   "10.19.45.21",
						},
						"10.20.6.0": {
							Status: "not-affected",
							Note:   "",
						},
						"10.21.20.1": {
							Status: "not-affected",
							Note:   "",
						},
					},
				},
			},
		},
		{
			name:     "multiple packages",
			filePath: "./testdata/multiple_packages",
			want: &Vulnerability{
				Candidate:   "CVE-2015-8985",
				PublicDate:  time.Date(2017, 3, 20, 0, 0, 0, 0, time.UTC),
				Description: "The pop_fail_stack function in the GNU C Library (aka glibc or libc6) allows context-dependent attackers to cause a denial of service (assertion failure and application crash) via vectors related to extended regular expression processing.",
				Notes: []string{
					"glibc",
				},
				Priority: "medium",
				Patches: map[Package]Statuses{
					Package("glibc"): {
						"10.18.44.1": {
							Status: "pending",
							Note:   "",
						},
						"10.19.45.1": {
							Status: "pending",
							Note:   "",
						},
					},
					Package("eglibc"): {
						"10.18.44.1": {
							Status: "pending",
							Note:   "",
						},
						"10.19.45.1": {
							Status: "pending",
							Note:   "",
						},
					},
				},
			},
		},
		{
			name:     "with comments and line breaks",
			filePath: "./testdata/with_comments_and_line_breaks",
			want: &Vulnerability{
				Candidate:   "CVE-2022-3134",
				PublicDate:  time.Date(2022, 9, 6, 0, 0, 0, 0, time.UTC),
				Description: "Use After Free in GitHub repository vim/vim prior to 9.0.0389.",
				Priority:    "high",
				Bugs: []string{
					"LINCD-10301",
					"LIN1022-1711",
					"LIN1021-4364",
					"LIN1019-8796",
					"LIN1018-9727",
				},
				Patches: map[Package]Statuses{
					Package("vim"): {
						"10.18.44.1": {
							Status: "released",
							Note:   "10.18.44.28",
						},
						"10.19.45.1": {
							Status: "released",
							Note:   "10.19.45.26",
						},
						"10.20.6.0": {
							Status: "not-affected",
							Note:   "",
						},
						"10.21.20.1": {
							Status: "released",
							Note:   "10.21.20.14",
						},
						"10.22.33.1": {
							Status: "not-affected",
							Note:   "",
						},
					},
				},
			},
		},
		{
			name:     "multiple multiline note",
			filePath: "./testdata/multiple_multiline_note",
			want: &Vulnerability{
				Candidate:   "CVE-2012-0880",
				PublicDate:  time.Date(2017, 8, 8, 0, 0, 0, 0, time.UTC),
				Description: "Apache Xerces-C++ allows remote attackers to cause a denial of service (CPU consumption) via a crafted message sent to an XML service that causes hash table collisions.",
				Priority:    "high",
				Notes: []string{
					"note 1 line 1 note 1 line 2",
					"note 2 line 1 note 2 line 2",
				},
				Bugs: []string{
					"LIN10-1106",
				},
				Patches: map[Package]Statuses{
					Package("xerces"): {
						"10.17.41.1": {
							Status: "released",
							Note:   "10.17.41.1",
						},
						"10.18.44.1": {
							Status: "ignored",
							Note:   "will not fix",
						},
						"10.19.45.1": {
							Status: "ignored",
							Note:   "will not fix",
						},
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.Open(tc.filePath)
			require.NoError(t, err)
			defer f.Close()

			got, gotErr := parse(f)
			assert.Equal(t, tc.wantErr, gotErr)
			assert.Equal(t, tc.want, got)
		})
	}
}
