package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	"time"
)

func main() {
	issuer := ""                // issuer base url (with https:// prefix, without trailing slash suffix) goes here
	keyId := ""                 // kms key arn goes here
	audience := ""              // audience (as defined in aws iam identity center)
	appArn := ""                // app arn (looks like arn:aws:sso::096661570446:application/ssoins-8259f0307527d298/apl-26da2b83fa412b6e)
	identityBearerRoleArn := "" // identity bearer, i.e. the one from the cfn template
	userEmail := ""             // user email goes here

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		panic(err)
	}

	signer, err := kmssigner.New(kms.NewFromConfig(cfg), keyId)
	if err != nil {
		panic(err)
	}

	method := &kmsSigningMethod{signer}

	outputToken := jwt.NewWithClaims(method, jwt.MapClaims(map[string]interface{}{
		"iss":   issuer,
		"email": userEmail, // this assumes you've defined email as the way to identify users in aws iam identity center
		"aud":   audience,
		"jti":   hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nbf":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}))
	outputToken.Header["kid"] = keyId

	// this creates the oidc jwt we are going to send to aws iic
	signedJwt, err := outputToken.SignedString(nil)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	api := ssooidc.NewFromConfig(cfg)
	resp, err := api.CreateTokenWithIAM(ctx, &ssooidc.CreateTokenWithIAMInput{
		GrantType: aws.String("urn:ietf:params:oauth:grant-type:jwt-bearer"),
		ClientId:  aws.String(appArn),
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

	stsApi := sts.NewFromConfig(cfg)
	stsresp, err := stsApi.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(identityBearerRoleArn),
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

	s3api := s3control.NewFromConfig(cfg, func(options *s3control.Options) {
		options.Credentials = creds
	},
	)

	// todo: nathan knows what to do from here
	_, err = s3api.GetDataAccess(ctx, &s3control.GetDataAccessInput{
		AccountId:  aws.String("nathan-account-id"),
		Permission: s3types.PermissionReadwrite,
		Target:     aws.String("s3://nathan-bucket/*"),
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
