package slip10

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"

	btcutil "github.com/FactomProject/btcutilecc"
)

var (
	// CurveBitcoin generates keys for the secp256k1 curve (equivalent to BIP32)
	CurveBitcoin = &curve{
		Curve:         btcutil.Secp256k1(),
		hmacKey:       []byte("Bitcoin seed"),
		isModernCurve: true,
	}

	// CurveP256 generates keys for the NIST P-256 curve
	CurveP256 = &curve{
		Curve:         elliptic.P256(),
		hmacKey:       []byte("Nist256p1 seed"),
		isModernCurve: true,
	}

	// CurveEd25519 generates keys for the ed25519 curve
	CurveEd25519 = &curve{
		modernCurve:   Ed25519Curve(),
		hmacKey:       []byte("ed25519 seed"),
		isModernCurve: false,
	}
)

const (
	// FirstHardenedChild is the index of the firxt "harded" child key as per the
	// bip32 spec
	FirstHardenedChild = uint32(0x80000000)

	// PublicKeyCompressedLength is the byte count of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	// PrivateWalletVersion is the version flag for serialized private keys
	PrivateWalletVersion, _ = hex.DecodeString("0488ADE4")

	// PublicWalletVersion is the version flag for serialized private keys
	PublicWalletVersion, _ = hex.DecodeString("0488B21E")

	// ErrSerializedKeyWrongSize is returned when trying to deserialize a key that
	// has an incorrect length
	ErrSerializedKeyWrongSize = errors.New("Serialized keys should by exactly 82 bytes")

	// ErrHardnedChildPublicKey is returned when trying to create a harded child
	// of the public key
	ErrHardnedChildPublicKey = errors.New("Can't create hardened child for public key")

	// ErrInvalidChecksum is returned when deserializing a key with an incorrect
	// checksum
	ErrInvalidChecksum = errors.New("Checksum doesn't match")

	// ErrInvalidPrivateKey is returned when a derived private key is invalid
	ErrInvalidPrivateKey = errors.New("Invalid private key")

	// ErrInvalidPublicKey is returned when a derived public key is invalid
	ErrInvalidPublicKey = errors.New("Invalid public key")

	// ErrInvalidCurve is returned when a curve is invalid with current operation
	ErrInvalidCurve = errors.New("Invalid curve")
)

// Key represents a bip32 extended key
type Key struct {
	Key         []byte // 33 bytes
	Version     []byte // 4 bytes
	ChildNumber []byte // 4 bytes
	FingerPrint []byte // 4 bytes
	ChainCode   []byte // 32 bytes
	Depth       byte   // 1 bytes
	IsPrivate   bool   // unserialized

	curve *curve
}

// NewMasterKey creates a new Bitcoin master extended key from a seed
func NewMasterKey(seed []byte) (*Key, error) {
	return NewMasterKeyWithCurve(seed, CurveBitcoin)
}

// NewMasterKey creates a new master extended key from a seed using the given curve

func NewMasterKeyWithCurve(seed []byte, curve *curve) (*Key, error) {
	// Generate key and chaincode
	var keyBytes []byte
	var chainCode []byte
	for {
		hmac := hmac.New(sha512.New, curve.hmacKey)
		_, err := hmac.Write(seed)
		if err != nil {
			return nil, err
		}
		intermediary := hmac.Sum(nil)

		// Split it into our key and chain code
		keyBytes = intermediary[:32]
		chainCode = intermediary[32:]

		if !curve.isModernCurve {
			break
		}

		// Validate key
		err = curve.validatePrivateKey(keyBytes)
		if err != nil && errors.Is(err, ErrInvalidPrivateKey) {
			seed = intermediary
			continue
		} else if err != nil {
			return nil, err
		}
		break
	}

	// Create the key struct
	key := &Key{
		Version:     PrivateWalletVersion,
		ChainCode:   chainCode,
		Key:         keyBytes,
		Depth:       0x0,
		ChildNumber: []byte{0x00, 0x00, 0x00, 0x00},
		FingerPrint: []byte{0x00, 0x00, 0x00, 0x00},
		IsPrivate:   true,
		curve:       curve,
	}

	return key, nil
}

// NewChildKey derives a child key from a given parent as outlined by bip32
func (key *Key) NewChildKey(childIdx uint32) (*Key, error) {
	if !key.curve.isModernCurve && childIdx < FirstHardenedChild {
		return nil, ErrInvalidCurve
	}
	// Fail early if trying to create hardned child from public key
	if !key.IsPrivate && childIdx >= FirstHardenedChild {
		return nil, ErrHardnedChildPublicKey
	}

	intermediary, err := key.getIntermediary(childIdx)
	if err != nil {
		return nil, err
	}

	// Create child Key with data common to all both scenarios
	childKey := &Key{
		ChildNumber: uint32Bytes(childIdx),
		ChainCode:   intermediary[32:],
		Depth:       key.Depth + 1,
		IsPrivate:   key.IsPrivate,
		curve:       key.curve,
	}

	// Bip32 CKDpriv
	if key.IsPrivate {
		childKey.Version = PrivateWalletVersion
		fingerprint, err := hash160(key.curve.publicKeyForPrivateKey(key.Key))
		if err != nil {
			return nil, err
		}

		childKey.FingerPrint = fingerprint[:4]
		if !key.curve.isModernCurve {
			childKey.Key = intermediary[:32]
			return childKey, nil
		}

		childKey.Key = key.curve.addPrivateKeys(intermediary[:32], key.Key)

		// Validate key
		err = key.curve.validatePrivateKey(childKey.Key)
		if err != nil {
			// TODO: This error should be handeled internally according to slip0010
			return nil, err
		}
		// Bip32 CKDpub
	} else {
		if !key.curve.isModernCurve {
			return nil, ErrInvalidCurve
		}

		keyBytes := key.curve.publicKeyForPrivateKey(intermediary[:32])

		// Validate key
		err := key.curve.validateChildPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}

		childKey.Version = PublicWalletVersion
		fingerprint, err := hash160(key.Key)
		if err != nil {
			return nil, err
		}
		childKey.FingerPrint = fingerprint[:4]
		childKey.Key = key.curve.addPublicKeys(keyBytes, key.Key)
	}

	return childKey, nil
}

func (key *Key) getIntermediary(childIdx uint32) ([]byte, error) {
	// Get intermediary to create key and chaincode from
	// Hardened children are based on the private key
	// NonHardened children are based on the public key
	childIndexBytes := uint32Bytes(childIdx)

	var data []byte
	if childIdx >= FirstHardenedChild {
		data = append([]byte{0x0}, key.Key...)
	} else {
		if key.IsPrivate {
			data = key.curve.publicKeyForPrivateKey(key.Key)
		} else {
			data = key.Key
		}
	}
	data = append(data, childIndexBytes...)

	hmac := hmac.New(sha512.New, key.ChainCode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	return hmac.Sum(nil), nil
}

// PublicKey returns the public version of key or return a copy
// The 'Neuter' function from the bip32 spec
func (key *Key) PublicKey() *Key {
	keyBytes := key.Key

	if key.IsPrivate {
		keyBytes = key.curve.publicKeyForPrivateKey(keyBytes)
	}

	return &Key{
		Version:     PublicWalletVersion,
		Key:         keyBytes,
		Depth:       key.Depth,
		ChildNumber: key.ChildNumber,
		FingerPrint: key.FingerPrint,
		ChainCode:   key.ChainCode,
		IsPrivate:   false,
		curve:       key.curve,
	}
}

// Serialize a Key to a 78 byte byte slice
func (key *Key) Serialize() ([]byte, error) {
	if key.curve != CurveBitcoin {
		return nil, errors.New("serialization only supported for Bitcoin keys")
	}

	// Private keys should be prepended with a single null byte
	keyBytes := key.Key
	if key.IsPrivate {
		keyBytes = append([]byte{0x0}, keyBytes...)
	}

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	buffer.Write(key.Version)
	buffer.WriteByte(key.Depth)
	buffer.Write(key.FingerPrint)
	buffer.Write(key.ChildNumber)
	buffer.Write(key.ChainCode)
	buffer.Write(keyBytes)

	// Append the standard doublesha256 checksum
	serializedKey, err := addChecksumToBytes(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	return serializedKey, nil
}

// B58Serialize encodes the Key in the standard Bitcoin base58 encoding
func (key *Key) B58Serialize() string {
	serializedKey, err := key.Serialize()
	if err != nil {
		return ""
	}

	return base58Encode(serializedKey)
}

// String encodes the Key in the standard Bitcoin base58 encoding
func (key *Key) String() string {
	return key.B58Serialize()
}

// Deserialize a byte slice into a Key
func Deserialize(data []byte) (*Key, error) {
	if len(data) != 82 {
		return nil, ErrSerializedKeyWrongSize
	}
	var key = &Key{}
	key.Version = data[0:4]
	key.Depth = data[4]
	key.FingerPrint = data[5:9]
	key.ChildNumber = data[9:13]
	key.ChainCode = data[13:45]
	key.curve = CurveBitcoin

	if data[45] == byte(0) {
		key.IsPrivate = true
		key.Key = data[46:78]
	} else {
		key.IsPrivate = false
		key.Key = data[45:78]
	}

	// validate checksum
	cs1, err := checksum(data[0 : len(data)-4])
	if err != nil {
		return nil, err
	}

	cs2 := data[len(data)-4:]
	for i := range cs1 {
		if cs1[i] != cs2[i] {
			return nil, ErrInvalidChecksum
		}
	}
	return key, nil
}

// B58Deserialize deserializes a Key encoded in base58 encoding
func B58Deserialize(data string) (*Key, error) {
	b, err := base58Decode(data)
	if err != nil {
		return nil, err
	}
	return Deserialize(b)
}

// NewSeed returns a cryptographically secure seed
func NewSeed() ([]byte, error) {
	// Well that easy, just make go read 256 random bytes into a slice
	s := make([]byte, 256)
	_, err := rand.Read(s)
	return s, err
}
