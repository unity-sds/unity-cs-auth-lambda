# Unity API Gateway - Common Lambda Authorizer Function

This is a token-based authorizer function to allow only JWT access tokens issued for the client IDs of the Unity Cognito 
user pool.

The JWT access token is verified using the [aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify) JavaScript library developed by the AWS Labs .

This authorizer can be used to verify JWT access tokens issued for multiple client IDs, presented as a 
comma seperated list. At the moment Unity uses only one user pool. However, it is possible to easily support 
the verification of JWTs issued by multiple user pools also, as explained in [Trusting multiple User Pools](https://github.com/awslabs/aws-jwt-verify#trusting-multiple-user-pools).

### Steps to use this lambda authorizer function:

1. Get the source code as follows.
```shell
git clone https://github.com/unity-sds/unity-cs-auth-lambda.git
```

2. Change current directory to `unity-cs-auth-lambda`

```shell
cd unity-cs-auth-lambda
```

3. Execute the following command to get the npm modules (make sure that you have [npm setup](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) in your computer before this step)

```shell
npm install
```

4. Create a deployment package as a ZIP file.

```shell
zip -r ucs-common-lambda-auth.zip .
```

5. Create a lambda function on AWS as explained in https://docs.aws.amazon.com/lambda/latest/dg/getting-started.html

6. Deploy the previously created ZIP file as explained in https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-package.html#gettingstarted-package-zip 

7. After deploying the lambda function, go to the lambda function in AWS Console and  click on Configuration -> Environment variables.

8. Configure the following 3 environment variables (The correct values can be obtained by checking the Cognito Unity 
 User Pool or contacting the Unity Common Services team).
   * COGNITO_USER_POOL_ID = <COGNITO_USER_POOL_ID>
   * COGNITO_CLIENT_ID_LIST = <COMMA_SEPERATED_LIST_OF_CLIENT_IDS>
   * COGNITO_GROUPS_ALLOWED = <COMMA_SEPERATED_LIST_OF_COGNITO_USER_GROUPS>

After above steps, the lambda functions can be used in API Gateway Authorizers.
