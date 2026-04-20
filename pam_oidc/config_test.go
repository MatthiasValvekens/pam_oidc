// Copyright (c) 2021, salesforce.com, inc.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// For full license text, see the LICENSE.txt file in the repo root or https://opensource.org/licenses/BSD-3-Clause

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestParseConfigFromArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    *config
		wantErr string
	}{
		{
			name: "basic with defaults",
			args: []string{"issuer=https://example.com", "aud=example-aud"},
			want: &config{
				Issuer:   "https://example.com",
				Aud:      "example-aud",
				CacheTTL: 12 * time.Hour, // default
			},
		},
		{
			name: "basic overriding defaults",
			args: []string{"issuer=https://example.com", "aud=example-aud", "user_template={{.Email}}", "groups_claim_key=roles", "authorized_groups=foo,bar,baz", "require_acr=foo", "http_proxy=http://example.com:8080"},
			want: &config{
				Issuer:           "https://example.com",
				Aud:              "example-aud",
				UserTemplate:     `{{.Email}}`,
				GroupsClaimKey:   "roles",
				AuthorizedGroups: []string{"foo", "bar", "baz"},
				RequireACRs:      []string{"foo"},
				HTTPProxy:        "http://example.com:8080",
				CacheTTL:         12 * time.Hour, // default
			},
		},
		{
			name: "basic overriding defaults required_acrs",
			args: []string{"issuer=https://example.com", "aud=example-aud", "user_template={{.Email}}", "groups_claim_key=roles", "authorized_groups=foo,bar,baz", "require_acrs=acr1,acr2,acr3", "http_proxy=http://example.com:8080"},
			want: &config{
				Issuer:           "https://example.com",
				Aud:              "example-aud",
				UserTemplate:     `{{.Email}}`,
				GroupsClaimKey:   "roles",
				AuthorizedGroups: []string{"foo", "bar", "baz"},
				RequireACRs:      []string{"acr1", "acr2", "acr3"},
				HTTPProxy:        "http://example.com:8080",
				CacheTTL:         12 * time.Hour, // default
			},
		},
		{
			name: "with cache_dir",
			args: []string{"issuer=https://example.com", "aud=example-aud", "cache_dir=/var/cache/pam_oidc"},
			want: &config{
				Issuer:   "https://example.com",
				Aud:      "example-aud",
				CacheDir: "/var/cache/pam_oidc",
				CacheTTL: 12 * time.Hour, // default
			},
		},
		{
			name: "cache_dir optional",
			args: []string{"issuer=https://example.com", "aud=example-aud"},
			want: &config{
				Issuer:   "https://example.com",
				Aud:      "example-aud",
				CacheTTL: 12 * time.Hour, // default
			},
		},
		{
			name: "with cache_ttl",
			args: []string{"issuer=https://example.com", "aud=example-aud", "cache_dir=/var/cache/pam_oidc", "cache_ttl=24h"},
			want: &config{
				Issuer:   "https://example.com",
				Aud:      "example-aud",
				CacheDir: "/var/cache/pam_oidc",
				CacheTTL: 24 * time.Hour,
			},
		},
		{
			name: "cache_ttl default",
			args: []string{"issuer=https://example.com", "aud=example-aud", "cache_dir=/var/cache/pam_oidc"},
			want: &config{
				Issuer:   "https://example.com",
				Aud:      "example-aud",
				CacheDir: "/var/cache/pam_oidc",
				CacheTTL: 12 * time.Hour, // default when not specified
			},
		},
		{
			name:    "invalid cache_ttl",
			args:    []string{"issuer=https://example.com", "aud=example-aud", "cache_ttl=invalid"},
			wantErr: "invalid cache_ttl",
		},
		{
			name:    "non-positive cache_ttl",
			args:    []string{"issuer=https://example.com", "aud=example-aud", "cache_ttl=0s"},
			wantErr: "invalid cache_ttl: must be > 0",
		},

		{
			name:    "invalid option",
			args:    []string{"issuer=https://example.com", "invalid=foo"},
			wantErr: "unknown option: invalid",
		},
	}

	for _, tc := range cases {
		tc := tc

		config, err := configFromArgs(tc.args)
		if err != nil && tc.wantErr == "" {
			t.Fatalf("wanted no error, but got %v", err)
		} else if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
			t.Fatalf("wanted error %v, but got %v", tc.wantErr, err)
		} else if err == nil && tc.wantErr != "" {
			t.Fatalf("wanted error %v, but got none", tc.wantErr)
		}

		if diff := cmp.Diff(config, tc.want); diff != "" {
			t.Errorf("diff: %v", diff)
		}
	}
}
