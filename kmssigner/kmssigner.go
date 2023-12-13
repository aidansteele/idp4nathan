package kmssigner

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"io"
)

var signatureMap = map[crypto.Hash]types.SigningAlgorithmSpec{
	crypto.SHA256: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	crypto.SHA384: types.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
	crypto.SHA512: types.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
}

type signer struct {
	api   *kms.Client
	keyId string
	pub   crypto.PublicKey
}

func New(api *kms.Client, keyId string) (crypto.Signer, error) {
	getPub, err := api.GetPublicKey(context.TODO(), &kms.GetPublicKeyInput{KeyId: &keyId})
	if err != nil {
		return nil, fmt.Errorf("getting public key: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(getPub.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &signer{
		api:   api,
		keyId: keyId,
		pub:   pub,
	}, nil
}

func (k *signer) Public() crypto.PublicKey {
	return k.pub
}

func (k *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sign, err := k.api.Sign(context.TODO(), &kms.SignInput{
		KeyId:            &k.keyId,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signatureMap[opts.HashFunc()],
	})
	if err != nil {
		return nil, fmt.Errorf("kms signing error: %w", err)
	}

	return sign.Signature, nil
}
