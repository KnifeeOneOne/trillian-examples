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

// Package api describes the external interface to the gossip hub.
package api

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/certificate-transparency-go/tls"
)

// PathPrefix is the common prefix for all HTTP entrypoints.
const PathPrefix = "/gossip/v0/"

// Add Log Head to Hub
// POST https://<hub server>/gossip/v0/add-log-head
// Inputs:
//    source_url: The URL from which the log head was obtained
//    head_data: The binary-encoded head
//    signature: The source log's signature over head_data.
// Outputs:
//
//  @@@@ index of existing entry, or signed promise to include?

// AddLogHeadPath is the final path component for this entrypoint.
const AddLogHeadPath = "add-log-head"

// AddLogHeadRequest represents the JSON request body sent to the add-log-head POST method.
type AddLogHeadRequest struct {
	SourceURL string `json:"source_url"`
	HeadData  []byte `json:"head_data"`
	Signature []byte `json:"signature"`
}

// Retrieve Latest Signed Tree Head for Hub
// GET https://<hub server>/gossip/v0/get-sth
// Inputs: None
// Outputs:
//    head_data: TLS-encoded tree head data
//    signature: signature over head_data.

// GetSTHPath is the final path component for this entrypoint.
const GetSTHPath = "get-sth"

// GetSTHResponse represents the JSON response to the get-sth GET method.
type GetSTHResponse struct {
	HeadData  []byte `json:"head_data"`
	Signature []byte `json:"signature"`
}

// Retrieve Consistency Proof between Tree Heads
// GET https://<hub server>/gossip/v0/get-sth-consistency
// Inputs:
//    first:  The tree_size of the first tree, in decimal.
//    second:  The tree_size of the second tree, in decimal.
// Both tree sizes must be from existing v1 STHs (Signed Tree Heads).
// Outputs:
//    consistency:  An array of Merkle Tree nodes, base64 encoded.

// GetSTHConsistencyPath is the final path component for this entrypoint.
const GetSTHConsistencyPath = "get-sth-consistency"
const (
	// GetSTHConsistencyFirst is the first parameter name.
	GetSTHConsistencyFirst = "first"
	// GetSTHConsistencySecond is the second parameter name.
	GetSTHConsistencySecond = "second"
)

// GetSTHConsistencyResponse represents the JSON response to the get-sth-consistency GET method.
type GetSTHConsistencyResponse struct {
	Consistency [][]byte `json:"consistency"`
}

// Retrieve Inclusion Proof from Log by Leaf Hash
// GET https://<log server>/gossip/v0/get-proof-by-hash
// Inputs:
//    hash:  A base64-encoded leaf hash, as described below.
//    tree_size:  The tree_size of the tree on which to base the proof in deciaml.
// Outputs:
//    leaf_index:  The 0-based index of the entry corresponding to the hash parameter.
//    audit_path:  An array of Merkle Tree node, base64 encoded.

// GetProofByHashPath is the final path component for this entrypoint.
const GetProofByHashPath = "get-proof-by-hash"
const (
	// GetProofByHashArg is the first parameter name.
	GetProofByHashArg = "hash"
	// GetProofByHashSize is the second parameter name.
	GetProofByHashSize = "tree_size"
)

// GetProofByHashResponse represents the JSON response to the get-proof-by-hash GET method.
type GetProofByHashResponse struct {
	LeafIndex int64    `json:"leaf_index"`
	AuditPath [][]byte `json:"audit_path"`
}

// Retrieve Entries from Log
// GET https://<log server>/gossip/v0/get-entries
// Inputs:
//    start:  0-based index of first entry to retrieve, in decimal.
//    end:  0-based index of last entry to retrieve, in decimal.
// Outputs:
//    entries:  An array of objects, each consisting of
//       leaf_data:  Base64-encoded data holding the TLS-encoding of a HubLeafEntry structure.
//       extra_data:  The base64-encoded unsigned data pertaining to the hub entry.

// GetEntriesPath is the final path component for this entrypoint.
const GetEntriesPath = "get-entries"

const (
	// GetEntriesStart is the first parameter name.
	GetEntriesStart = "start"
	// GetEntriesEnd is the second parameter name.
	GetEntriesEnd = "end"
)

// GetEntriesResponse respresents the JSON response to the get-entries GET method.
type GetEntriesResponse struct {
	Entries []LeafEntry `json:"entries"` // the list of returned entries
}

// LeafEntry represents a leaf in the Hub's Merkle tree.
type LeafEntry struct {
	LeafData  []byte `json:"leaf_data"`
	ExtraData []byte `json:"extra_data"`
}

// Retrieve Accepted Log Public Keys
// GET https://<log server>/gossip/v0/get-log-keys
// Inputs: None
// Outputs:
//   logs: An array of objects, each consisting of
//      url: The URL for the source log.
//      pub_key:  The base64-encoded public key for the source log.

// GetLogKeysPath is the final path component for this entrypoint.
const GetLogKeysPath = "get-log-keys"

// GetLogKeysResponse represents the JSON response to the get-log-keys GET method.
type GetLogKeysResponse struct {
	Entries []*LogKey `json:"entries"`
}

// LogKey holds key information about a source Log that is tracked by this hub.
type LogKey struct {
	URL    string `json:"url"`
	PubKey []byte `json:"pub_key"`
}

// HubLeafEntry describes a leaf entry in the hub's log. It is stored as the
// TLS-encoding of:
//   struct {
//     opaque<1..255> source_url;
//     opaque<1..65535> head_data;
//     opaque<1..65535> signature;
//   } HubLeafEntry;
type HubLeafEntry struct {
	SourceURL []byte `tls:"minlen:1,maxlen:255"`
	HeadData  []byte `tls:"minlen:1,maxlen:65535"`
	Signature []byte `tls:"minlen:1,maxlen:65535"`
}

// HubLeafHash calculates the leaf hash value for a hub leaf entry:
//   SHA256(0x00 || tls-encode(HubLeafEntry))
func HubLeafHash(entry *HubLeafEntry) ([]byte, error) {
	data, err := tls.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to tls.Marshal: %v", err)
	}
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil), nil
}
