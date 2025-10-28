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
	"io"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchEasyTierConfigServer{})
}

// MatchEasyTierConfigServer matches EasyTier config-server handshake packets.
type MatchEasyTierConfigServer struct{}

// CaddyModule returns the Caddy module information.
func (*MatchEasyTierConfigServer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.easytier_config_server",
		New: func() caddy.Module { return new(MatchEasyTierConfigServer) },
	}
}

// Match returns true if the connection looks like an EasyTier config-server handshake.
func (m *MatchEasyTierConfigServer) Match(cx *layer4.Connection) (bool, error) {
	if _, ok := cx.LocalAddr().(*net.UDPAddr); !ok {
		return false, nil
	}

	buf := make([]byte, easyTierHandshakeBytes)
	if _, err := io.ReadFull(cx, buf); err != nil {
		return false, err
	}

	msgType := buf[easyTierMsgTypeOffset]
	var msgTypeName string
	switch msgType {
	case easyTierMsgTypeSyn:
		msgTypeName = easyTierMsgTypeSynName
	case easyTierMsgTypeSack:
		msgTypeName = easyTierMsgTypeSackName
	default:
		return false, nil
	}

	if buf[easyTierPaddingOffset] != easyTierPaddingValue {
		return false, nil
	}

	payloadLen := binary.LittleEndian.Uint16(buf[easyTierLengthOffset : easyTierLengthOffset+easyTierLengthBytes])
	if payloadLen != easyTierPayloadBytes {
		return false, nil
	}

	if repl, ok := cx.Context.Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok && repl != nil {
		repl.Set(replacerKeyConnID, binary.LittleEndian.Uint32(buf[:easyTierMsgTypeOffset]))
		repl.Set(replacerKeyMsgType, msgTypeName)
		repl.Set(replacerKeyMagic, binary.LittleEndian.Uint64(buf[easyTierMagicOffset:]))
	}

	return true, nil
}

// UnmarshalCaddyfile sets up the MatchEasyTierConfigServer from Caddyfile tokens. Syntax:
//
//	easytier_config_server
func (m *MatchEasyTierConfigServer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}

	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection matcher '%s': blocks are not supported", wrapper)
	}

	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchEasyTierConfigServer)(nil)
	_ caddyfile.Unmarshaler = (*MatchEasyTierConfigServer)(nil)
)

const (
	easyTierHandshakeBytes       = 16
	easyTierMsgTypeOffset        = 4
	easyTierPaddingOffset        = 5
	easyTierLengthOffset         = 6
	easyTierLengthBytes          = 2
	easyTierPayloadBytes         = 8
	easyTierMagicOffset          = 8
	easyTierPaddingValue         = 0x00
	easyTierMsgTypeSyn     uint8 = 0x01
	easyTierMsgTypeSack    uint8 = 0x02

	easyTierMsgTypeSynName  = "syn"
	easyTierMsgTypeSackName = "sack"

	replacerKeyConnID  = "l4.easytier.conn_id"
	replacerKeyMsgType = "l4.easytier.msg_type"
	replacerKeyMagic   = "l4.easytier.magic"
)
