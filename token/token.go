package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aidansteele/idp4nathan/kmssigner"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Issuer                string `json:"issuer"`
	KeyId                 string `json:"keyId"`
	Audience              string `json:"audience"`
	AppArn                string `json:"appArn"`
	IdentityBearerRoleArn string `json:"identityBearerRoleArn"`
	UserEmail             string `json:"userEmail"`
	AccountId             string `json:"accountId"`
	Target                string `json:"target"`
}

func main() {
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		panic(err)
	}

	var cfg Config
	err = json.Unmarshal(configFile, &cfg)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic(err)
	}

	signer, err := kmssigner.New(kms.NewFromConfig(awsCfg), cfg.KeyId)
	if err != nil {
		panic(err)
	}

	method := &kmsSigningMethod{signer}

	outputToken := jwt.NewWithClaims(method, jwt.MapClaims(map[string]interface{}{
		"iss":   cfg.Issuer,
		"email": cfg.UserEmail,
		"aud":   cfg.Audience,
		"jti":   hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}))
	outputToken.Header["kid"] = cfg.KeyId

	// this creates the oidc jwt we are going to send to aws iic
	signedJwt, err := outputToken.SignedString(nil)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	api := ssooidc.NewFromConfig(awsCfg)
	resp, err := api.CreateTokenWithIAM(ctx, &ssooidc.CreateTokenWithIAMInput{
		GrantType: aws.String("urn:ietf:params:oauth:grant-type:jwt-bearer"),
		ClientId:  aws.String(cfg.AppArn),
		Assertion: aws.String(signedJwt),
	})
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	// aws iic sends us back a new oidc jwt. we have to parse its claims
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(*resp.IdToken, &claims)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	fmt.Printf("%#v\n", claims)

	identityContext := claims["sts:identity_context"].(string)

	stsApi := sts.NewFromConfig(awsCfg)
	stsresp, err := stsApi.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(cfg.IdentityBearerRoleArn),
		RoleSessionName: aws.String("my-role-session-with-identity-context"),
		ProvidedContexts: []types.ProvidedContext{
			{
				ProviderArn:      aws.String("arn:aws:iam::aws:contextProvider/IdentityCenter"),
				ContextAssertion: aws.String(identityContext),
			},
		},
	})
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	c := stsresp.Credentials
	creds := credentials.NewStaticCredentialsProvider(
		*c.AccessKeyId,
		*c.SecretAccessKey,
		*c.SessionToken,
	)

	s3api := s3control.NewFromConfig(awsCfg, func(options *s3control.Options) {
		options.Credentials = creds
	})

	_, err = s3api.GetDataAccess(ctx, &s3control.GetDataAccessInput{
		AccountId:  aws.String(cfg.AccountId),
		Permission: s3types.PermissionRead,
		Target:     aws.String(cfg.Target),
		Privilege:  s3types.PrivilegeDefault,
	})
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}

type kmsSigningMethod struct {
	crypto.Signer
}

func (m *kmsSigningMethod) Verify(signingString string, signature []byte, key interface{}) error {
	panic("verify not implemented")
}

func (m *kmsSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	digest := sha256.Sum256([]byte(signingString))

	sig, err := m.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing jwt: %w", err)
	}

	return sig, nil
}

func (m *kmsSigningMethod) Alg() string {
	return "RS256"
}
