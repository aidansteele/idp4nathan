Usage (avert your eyes if you are not @t04glovern)

```
# deploy the idp
sam build
sam deploy --stack-name idp4nathan --capabilities CAPABILITY_IAM --resolve-s3

# now paste the kms key id, idp url and role arn in token/token.go
# after that you can run this next command
go run ./token
```
