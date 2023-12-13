package main

import (
	"context"
	"crypto"
	"github.com/aidansteele/idp4nathan/kmssigner"
	"github.com/aws/aws-lambda-go/lambdaurl"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"net/http"
	"os"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic(err)
	}

	keyId := os.Getenv("KEY_ID")

	signer, err := kmssigner.New(kms.NewFromConfig(cfg), keyId)
	if err != nil {
		panic(err)
	}

	srv := &Server{
		keyId:  keyId,
		signer: signer,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", srv.handleDiscoveryDocument)
	mux.HandleFunc("/.well-known/jwks", srv.handleJwks)

	lambdaurl.Start(mux)
}

type Server struct {
	keyId  string
	signer crypto.Signer
}
