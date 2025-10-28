// Copyright 2024 VNXME
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

package l4easytier

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/mholt/caddy-l4/layer4"
)

func TestMatchEasyTierConfigServer_Match(t *testing.T) {
	tests := []struct {
		name            string
		packet          []byte
		useUDP          bool
		expect          bool
		expectedMsgType string
		expectedConnID  uint32
		expectedMagic   uint64
	}{
		{
			name:            "syn",
			packet:          newHandshakePacket(easyTierMsgTypeSyn, easyTierPaddingValue, easyTierPayloadBytes),
			useUDP:          true,
			expect:          true,
			expectedMsgType: easyTierMsgTypeSynName,
			expectedConnID:  0xAABBCCDD,
			expectedMagic:   0x0123456789ABCDEF,
		},
		{
			name:            "sack",
			packet:          newHandshakePacket(easyTierMsgTypeSack, easyTierPaddingValue, easyTierPayloadBytes),
			useUDP:          true,
			expect:          true,
			expectedMsgType: easyTierMsgTypeSackName,
			expectedConnID:  0xAABBCCDD,
			expectedMagic:   0x0123456789ABCDEF,
		},
		{
			name:   "unexpected-msg-type",
			packet: newHandshakePacket(0x03, easyTierPaddingValue, easyTierPayloadBytes),
			useUDP: true,
			expect: false,
		},
		{
			name:   "unexpected-padding",
			packet: newHandshakePacket(easyTierMsgTypeSyn, 0x01, easyTierPayloadBytes),
			useUDP: true,
			expect: false,
		},
		{
			name:   "unexpected-length",
			packet: newHandshakePacket(easyTierMsgTypeSyn, easyTierPaddingValue, easyTierPayloadBytes+1),
			useUDP: true,
			expect: false,
		},
		{
			name:   "non-udp",
			packet: nil,
			useUDP: false,
			expect: false,
		},
	}

	matcher := &MatchEasyTierConfigServer{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() {
				_ = client.Close()
			})

			var serverConn net.Conn = server
			if tc.useUDP {
				serverConn = &fakeUDPConn{Conn: server}
			}
			t.Cleanup(func() {
				_ = serverConn.Close()
			})

			cx := layer4.WrapConnection(serverConn, []byte{}, zap.NewNop())

			if len(tc.packet) > 0 {
				go func() {
					_, _ = client.Write(tc.packet)
					_ = client.Close()
				}()
			} else {
				go func() {
					_ = client.Close()
				}()
			}

			matched, err := matcher.Match(cx)
			assertNoError(t, err)

			if matched != tc.expect {
				t.Fatalf("expected match=%v, got %v", tc.expect, matched)
			}

			if matched && tc.expectedMsgType != "" {
				repl := cx.Context.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

				msgTypeVal, ok := repl.Get(replacerKeyMsgType)
				if !ok {
					t.Fatalf("expected replacer key %q to be set", replacerKeyMsgType)
				}
				msgType, ok := msgTypeVal.(string)
				if !ok {
					t.Fatalf("expected msg type to be string, got %T", msgTypeVal)
				}
				if msgType != tc.expectedMsgType {
					t.Fatalf("expected msg type %q, got %q", tc.expectedMsgType, msgType)
				}

				connIDVal, ok := repl.Get(replacerKeyConnID)
				if !ok {
					t.Fatalf("expected replacer key %q to be set", replacerKeyConnID)
				}
				connID, ok := connIDVal.(uint32)
				if !ok {
					t.Fatalf("expected conn_id to be uint32, got %T", connIDVal)
				}
				if connID != tc.expectedConnID {
					t.Fatalf("expected conn_id 0x%08X, got 0x%08X", tc.expectedConnID, connID)
				}

				magicVal, ok := repl.Get(replacerKeyMagic)
				if !ok {
					t.Fatalf("expected replacer key %q to be set", replacerKeyMagic)
				}
				magic, ok := magicVal.(uint64)
				if !ok {
					t.Fatalf("expected magic to be uint64, got %T", magicVal)
				}
				if magic != tc.expectedMagic {
					t.Fatalf("expected magic 0x%016X, got 0x%016X", tc.expectedMagic, magic)
				}
			}
		})
	}
}

func newHandshakePacket(msgType uint8, padding uint8, payloadLen uint16) []byte {
	packet := make([]byte, easyTierHandshakeBytes)
	binary.LittleEndian.PutUint32(packet[:4], 0xAABBCCDD)
	packet[easyTierMsgTypeOffset] = msgType
	packet[easyTierPaddingOffset] = padding
	binary.LittleEndian.PutUint16(packet[easyTierLengthOffset:], payloadLen)
	binary.LittleEndian.PutUint64(packet[8:], 0x0123456789ABCDEF)
	return packet
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("unexpected error: %v", err)
	}
}

type fakeUDPConn struct {
	net.Conn
}

func (c *fakeUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

// Interface guard
var _ net.Conn = (*fakeUDPConn)(nil)
