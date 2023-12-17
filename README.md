Usage (avert your eyes if you are not @t04glovern)

```bash
# install aws-sam-cli
pip install aws-sam-cli

# deploy the idp
sam build
sam deploy --stack-name idp4nathan --capabilities CAPABILITY_IAM --resolve-s3

# setup your config.json file with the outputs from the AWS SAM CLI deployment
export OUTPUTS_JSON=$(aws cloudformation describe-stacks --stack-name idp4nathan --query 'Stacks[0].Outputs' --output json)

issuer=$(echo $OUTPUTS_JSON | jq -r '.[] | select(.OutputKey=="Issuer") | .OutputValue')
keyId=$(echo $OUTPUTS_JSON | jq -r '.[] | select(.OutputKey=="RsaKey") | .OutputValue')
identityBearerRoleArn=$(echo $OUTPUTS_JSON | jq -r '.[] | select(.OutputKey=="IdentityBearer") | .OutputValue')

# Remove trailing '/' from issuer URL if present
issuer=${issuer%/}

# Set other values (you need to fill these based on your configuration of s3 access grants and IAM IIC)
audience="AUDIENCERANDOM3TRINGG03SH3RE"
appArn="arn:aws:sso::account-id:application/ssoins-example/apl-example"
userEmail="user@example.com"
accountId="123456789012"
target="s3://example-bucket/path/to/resource"

# Create config.json file
cat << EOF > config.json
{
    "issuer": "$issuer",
    "keyId": "$keyId",
    "audience": "$audience",
    "appArn": "$appArn",
    "identityBearerRoleArn": "$identityBearerRoleArn",
    "userEmail": "$userEmail",
    "accountId": "$accountId",
    "target": "$target"
}
EOF

# after that you can run this next command
go run ./token
```
