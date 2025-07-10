package slip10

import (
	"bytes"
	"crypto/ed25519"

	"github.com/pkg/errors"
)

type ed25519Curve struct {
}

func Ed25519Curve() ed25519Curve {
	return ed25519Curve{}
}

func (c ed25519Curve) keypair(key []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	reader := bytes.NewReader(key)
	pub, priv, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Invalid key")
	}

	return pub[:], priv[:], nil
}

// PublicKey returns public key with 0x00 prefix, as specified in the slip-10
// https://github.com/satoshilabs/slips/blob/master/slip-0010/testvectors.py#L64
func (c ed25519Curve) PublicKey(key []byte) []byte {
	pub, _, _ := c.keypair(key)
	return append([]byte{0x00}, pub...)
}

func (c ed25519Curve) PrivateKey(key []byte) []byte {
	_, priv, _ := c.keypair(key)
	return priv
}
