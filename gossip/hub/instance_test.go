// Copyright 2018 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hub

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian-examples/gossip/hub/configpb"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
	"github.com/google/trillian/monitoring"

	_ "github.com/google/trillian/crypto/keys/pem/proto" // Register PEMKeyFile ProtoHandler
)

// Copy of c-t-go/trillian/testdata/keys.go DemoPublicKey
const testPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsAVg3YB0tOFf3DdC2YHPL2WiuCNR
1iywqGjjtu2dAdWktWqgRO4NTqPJXUggSQL3nvOupHB4WZFZ4j3QhtmWRg==
-----END PUBLIC KEY-----`

func TestSetUpInstance(t *testing.T) {
	ctx := context.Background()

	privKey, err := ptypes.MarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/hub-server.privkey.pem", Password: "dirk"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}
	missingPrivKey, err := ptypes.MarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/bogus.privkey.pem", Password: "dirk"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}
	wrongPassPrivKey, err := ptypes.MarshalAny(&keyspb.PEMKeyFile{Path: "../testdata/hub-server.privkey.pem", Password: "dirkly"})
	if err != nil {
		t.Fatalf("Could not marshal private key proto: %v", err)
	}
	block, _ := pem.Decode([]byte(testPubKey))
	if block == nil {
		t.Fatalf("Could not unmarshal public key")
	}
	pubKeyData := block.Bytes

	var tests = []struct {
		desc    string
		cfg     configpb.HubConfig
		wantErr string
	}{
		{
			desc: "valid",
			cfg: configpb.HubConfig{
				LogId:  1,
				Prefix: "hub",
				SourceLog: []*configpb.TrackedLog{
					{
						Name:          "fred",
						Url:           "http://example.com/fred",
						HashAlgorithm: sigpb.DigitallySigned_SHA256,
						PublicKey:     &keyspb.PublicKey{Der: pubKeyData},
					},
				},
				PrivateKey: privKey,
			},
		},
		{
			desc: "no-source-logs",
			cfg: configpb.HubConfig{
				LogId:      1,
				Prefix:     "hub",
				PrivateKey: privKey,
			},
			wantErr: "specify SourceLog",
		},
		{
			desc: "no-priv-key",
			cfg: configpb.HubConfig{
				LogId:  1,
				Prefix: "hub",
				SourceLog: []*configpb.TrackedLog{
					{
						Name:          "fred",
						Url:           "http://example.com/fred",
						HashAlgorithm: sigpb.DigitallySigned_SHA256,
						PublicKey:     &keyspb.PublicKey{Der: pubKeyData},
					},
				},
			},
			wantErr: "specify PrivateKey",
		},
		{
			desc: "missing-privkey",
			cfg: configpb.HubConfig{
				LogId:  1,
				Prefix: "hub",
				SourceLog: []*configpb.TrackedLog{
					{
						Name:          "fred",
						Url:           "http://example.com/fred",
						HashAlgorithm: sigpb.DigitallySigned_SHA256,
						PublicKey:     &keyspb.PublicKey{Der: pubKeyData},
					},
				},
				PrivateKey: missingPrivKey,
			},
			wantErr: "failed to load private key",
		},
		{
			desc: "privkey-wrong-password",
			cfg: configpb.HubConfig{
				LogId:  1,
				Prefix: "hub",
				SourceLog: []*configpb.TrackedLog{
					{
						Name:          "fred",
						Url:           "http://example.com/fred",
						HashAlgorithm: sigpb.DigitallySigned_SHA256,
						PublicKey:     &keyspb.PublicKey{Der: pubKeyData},
					},
				},
				PrivateKey: wrongPassPrivKey,
			},
			wantErr: "failed to load private key",
		},
		{
			desc: "unknown-hash-algorithm",
			cfg: configpb.HubConfig{
				LogId:  1,
				Prefix: "hub",
				SourceLog: []*configpb.TrackedLog{
					{
						Name:          "fred",
						Url:           "http://example.com/fred",
						HashAlgorithm: 99,
						PublicKey:     &keyspb.PublicKey{Der: pubKeyData},
					},
				},
				PrivateKey: privKey,
			},
			wantErr: "Failed to determine hash algorithm",
		},
	}

	opts := InstanceOptions{Deadline: time.Second, MaxGetEntries: 100, MetricFactory: monitoring.InertMetricFactory{}}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			if _, err := SetUpInstance(ctx, nil, &test.cfg, opts); err != nil {
				if test.wantErr == "" {
					t.Errorf("SetUpInstance()=_,%v; want _,nil", err)
				} else if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("SetUpInstance()=_,%v; want err containing %q", err, test.wantErr)
				}
				return
			}
			if test.wantErr != "" {
				t.Errorf("SetUpInstance()=_,nil; want err containing %q", test.wantErr)
			}
		})
	}
}

func TestValidateHubMultiConfig(t *testing.T) {
	var tests = []struct {
		desc    string
		cfg     configpb.HubMultiConfig
		wantErr string
	}{
		{
			desc: "missing-backend-name",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{BackendSpec: "testspec"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{},
			},
			wantErr: "empty backend name",
		},
		{
			desc: "missing-backend-spec",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{},
			},
			wantErr: "empty backend_spec",
		},
		{
			desc: "missing-backend-name-and-spec",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{},
					},
				},
				HubConfigs: &configpb.HubConfigSet{},
			},
			wantErr: "empty backend name",
		},
		{
			desc: "dup-backend-name",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "dup", BackendSpec: "testspec"},
						{Name: "dup", BackendSpec: "testspec"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{},
			},
			wantErr: "duplicate backend name",
		},
		{
			desc: "dup-backend-spec",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "backend1", BackendSpec: "testspec"},
						{Name: "backend2", BackendSpec: "testspec"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{},
			},
			wantErr: "duplicate backend spec",
		},
		{
			desc: "missing-backend-reference",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log2"},
					},
				},
			},
			wantErr: "empty backend",
		},
		{
			desc: "undefined-backend-reference",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1", BackendSpec: "testspec"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log2", Prefix: "prefix"},
					},
				},
			},
			wantErr: "undefined backend",
		},
		{
			desc: "empty-log-prefix",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1", BackendSpec: "testspec1"},
						{Name: "log2", BackendSpec: "testspec2"},
						{Name: "log3", BackendSpec: "testspec3"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log1", Prefix: "prefix1"},
						{HubBackendName: "log2"},
						{HubBackendName: "log3", Prefix: "prefix3"},
					},
				},
			},
			wantErr: "empty prefix",
		},
		{
			desc: "dup-log-prefix",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log1", Prefix: "prefix1", LogId: 1},
						{HubBackendName: "log1", Prefix: "prefix2", LogId: 2},
						{HubBackendName: "log1", Prefix: "prefix1", LogId: 3},
					},
				},
			},
			wantErr: "duplicate prefix",
		},
		{
			desc: "dup-log-ids-on-same-backend",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1", BackendSpec: "testspec1"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log1", Prefix: "prefix1", LogId: 1},
						{HubBackendName: "log1", Prefix: "prefix2", LogId: 1},
						{HubBackendName: "log1", Prefix: "prefix1", LogId: 1},
					},
				},
			},
			wantErr: "dup tree id",
		},
		{
			desc: "valid-config",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1", BackendSpec: "testspec1"},
						{Name: "log2", BackendSpec: "testspec2"},
						{Name: "log3", BackendSpec: "testspec3"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log1", Prefix: "prefix1", LogId: 1},
						{HubBackendName: "log2", Prefix: "prefix2", LogId: 2},
						{HubBackendName: "log3", Prefix: "prefix3", LogId: 3},
					},
				},
			},
		},
		{
			desc: "valid config dup ids on different backends",
			cfg: configpb.HubMultiConfig{
				Backends: &configpb.HubBackendSet{
					Backend: []*configpb.HubBackend{
						{Name: "log1", BackendSpec: "testspec1"},
						{Name: "log2", BackendSpec: "testspec2"},
						{Name: "log3", BackendSpec: "testspec3"},
					},
				},
				HubConfigs: &configpb.HubConfigSet{
					Config: []*configpb.HubConfig{
						{HubBackendName: "log1", Prefix: "prefix1", LogId: 999},
						{HubBackendName: "log2", Prefix: "prefix2", LogId: 999},
						{HubBackendName: "log3", Prefix: "prefix3", LogId: 999},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			_, err := ValidateHubMultiConfig(&test.cfg)
			if len(test.wantErr) == 0 && err != nil {
				t.Fatalf("ValidateHubMultiConfig()=%v, want: nil", err)
			}

			if len(test.wantErr) > 0 && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Errorf("ValidateHubMultiConfig()=%v, want: %v", err, test.wantErr)
			}
		})
	}
}
