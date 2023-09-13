# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import cdk_nag

from aws_cdk import (
    Aws as _aws,
    CfnOutput as _output,
    Duration,
    Stack,
    aws_apigatewayv2 as _apigw,
    aws_cognito as _cognito,
    aws_dynamodb as _dynamodb,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_secretsmanager as _secretsmanager
)

from constructs import Construct
from cdk_nag import NagSuppressions

class PjwtWithPkceStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)


        """
        GLOBAL CONFIGURATION ITEMS
        """

        api_version = self.node.try_get_context("api_version")
        authn_route = self.node.try_get_context("api_authn_route")
        callb_route = self.node.try_get_context("api_callback_route")
        token_route = self.node.try_get_context("api_token_route")


        """
        RESOURCE DEFINITIONS
        """

        # API Gateway base configuration - defining here to use API ID in building env vars for Lambda functions and Cognito Domain
        apigw_proxy_api = _apigw.CfnApi(
            self, "ApiGwProxyApi",
            description = "Handles requests and responses between Cognito and 3rd party IdP",
            name = construct_id + "Api",
            protocol_type = "HTTP",
            cors_configuration = _apigw.CfnApi.CorsProperty(
                allow_methods = ["GET", "POST"],
                allow_origins = ["*"]
            )
        )

        # DynamoDB table to store state id and generated code verifier during authorization (PKCE)
        dynamodb_state_table = _dynamodb.Table(
            self, "StateTable",
            partition_key = _dynamodb.Attribute(name = "state", type = _dynamodb.AttributeType.STRING),
            billing_mode = _dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute = "ttl"
        )

        # DynamoDB table to store authorization code with the associated code verfier during IdP authN response (PKCE)
        dynamodb_code_table = _dynamodb.Table(
            self, "CodeTable",
            partition_key = _dynamodb.Attribute(name = "auth_code", type = _dynamodb.AttributeType.STRING),
            billing_mode = _dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute = "ttl"
        )

        # Secrets Manager empty secret to hold the private key for private key JWT token request
        secretsmanager_private_key = _secretsmanager.Secret(
            self, "PrivateKey"
        )

        # Lambda Execution role for the authorize function
        lambda_function_authorize_exec_role = _iam.Role(
            self, "AuthorizeRole",
            assumed_by = _iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies = [
                _iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies = {
                "DynamoDbPolicy": _iam.PolicyDocument(
                    statements = [
                        _iam.PolicyStatement(
                            effect = _iam.Effect.ALLOW,
                            actions = ["dynamodb:DescribeTable", "dynamodb:PutItem"],
                            resources = [dynamodb_state_table.table_arn]
                        )
                    ]
                ),
                "SecretsManagerPolicy": _iam.PolicyDocument(
                    statements = [
                        _iam.PolicyStatement(
                            effect = _iam.Effect.ALLOW,
                            actions = ["secretsmanager:GetRandomPassword"],
                            resources = ["*"]
                        )
                    ]
                )
            }
        )

        # Lambda function to handle authorization requests when using PKCE
        lambda_function_authorize = _lambda.Function(
            self, "Authorize",
            runtime = _lambda.Runtime.PYTHON_3_10,
            code = _lambda.Code.from_asset("./lambda/authorize"),
            handler = "authorize_flow.handler",
            environment = {
                "ClientId": self.node.try_get_context("idp_client_id"),
                "DynamoDbStateTable": dynamodb_state_table.table_name,
                "IdpAuthUri": self.node.try_get_context("idp_issuer_url") + self.node.try_get_context("idp_auth_path"),
                "ProxyCallbackUri": f"{apigw_proxy_api.attr_api_endpoint}/{api_version}{callb_route}"
            },
            role = lambda_function_authorize_exec_role,
            log_retention = _logs.RetentionDays.FIVE_DAYS
        )

        # Lambda Execution role for the callback function
        lambda_function_callback_exec_role = _iam.Role(
            self, "CallbackRole",
            assumed_by = _iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies = [
                _iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies = {
                "DynamoDbPolicy": _iam.PolicyDocument(
                    statements = [
                        _iam.PolicyStatement(
                            effect = _iam.Effect.ALLOW,
                            actions = ["dynamodb:DescribeTable", "dynamodb:GetItem"],
                            resources = [dynamodb_state_table.table_arn]
                        ),
                        _iam.PolicyStatement(
                            effect = _iam.Effect.ALLOW,
                            actions = ["dynamodb:DescribeTable", "dynamodb:PutItem"],
                            resources = [dynamodb_code_table.table_arn]
                        )
                    ]
                )
            }
        )

        # Lambda function to handle the IdP's callback when using PKCE
        lambda_function_callback = _lambda.Function(
            self, "Callback",
            runtime=_lambda.Runtime.PYTHON_3_10,
            code=_lambda.Code.from_asset("./lambda/callback"),
            handler="callback_flow.handler",
            environment = {
                "CognitoIdpResponseUri": f"https://{apigw_proxy_api.attr_api_id}.auth.{_aws.REGION}.amazoncognito.com/oauth2/idpresponse",
                "DynamoDbCodeTable": dynamodb_code_table.table_name,
                "DynamoDbStateTable": dynamodb_state_table.table_name
            },
            role = lambda_function_callback_exec_role,
            log_retention = _logs.RetentionDays.FIVE_DAYS
        )

        # Lambda Execution role for the token function
        lambda_function_token_exec_role = _iam.Role(
            self, "TokenRole",
            assumed_by = _iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies = [
                _iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole")
            ],
            inline_policies = {
                "DynamoDbPolicy": _iam.PolicyDocument(
                    statements = [
                        _iam.PolicyStatement(
                            effect = _iam.Effect.ALLOW,
                            actions = ["dynamodb:DescribeTable", "dynamodb:GetItem"],
                            resources = [dynamodb_code_table.table_arn]
                        )
                    ]
                ),
                "SecretsManagerPolicy": _iam.PolicyDocument(
                    statements = [
                        _iam.PolicyStatement(
                            effect = _iam.Effect.ALLOW,
                            actions = ["secretsmanager:GetSecretValue"],
                            resources = [secretsmanager_private_key.secret_full_arn]
                        )
                    ]
                )
            }
        )

        # Lambda function to handle token requests
        lambda_function_token = _lambda.Function(
            self, "Token",
            runtime=_lambda.Runtime.PYTHON_3_10,
            code=_lambda.Code.from_asset("./lambda/token"),
            handler="token_flow.handler",
            timeout=Duration.seconds(30),
            environment = {
                "ClientId": self.node.try_get_context("idp_client_id"),
                "ClientSecret": self.node.try_get_context("idp_client_secret"),
                "DynamoDbCodeTable": dynamodb_code_table.table_name,
                "IdpIssuerUrl": self.node.try_get_context("idp_issuer_url"),
                "IdpTokenPath": self.node.try_get_context("idp_token_path"),
                "ResponseUri": f"{apigw_proxy_api.attr_api_endpoint}/{api_version}{callb_route}",
                "Pkce": str(self.node.try_get_context("pkce")),
                "Region": _aws.REGION,
                "SecretsManagerPrivateKey": secretsmanager_private_key.secret_name
            },
            role = lambda_function_token_exec_role,
            layers = [
                _lambda.LayerVersion(
                    self, "JwtLayer",
                    code = _lambda.Code.from_asset("./layers/token/"),
                    compatible_runtimes = [_lambda.Runtime.PYTHON_3_10]
                )
            ],
            log_retention = _logs.RetentionDays.FIVE_DAYS
        )

        # API Gateway Lambda integration for authorization
        apigw_proxy_integration_auth = _apigw.CfnIntegration(
            self, "ApiGwProxyIntegrationAuth",
            api_id = apigw_proxy_api.attr_api_id,
            integration_type = "AWS_PROXY",
            integration_uri = lambda_function_authorize.function_arn,
            integration_method = "GET",
            payload_format_version = "2.0"
        )

        # API Gateway Lambda integration for callback
        apigw_proxy_integration_callback= _apigw.CfnIntegration(
            self, "ApiGwProxyIntegrationCallback",
            api_id = apigw_proxy_api.attr_api_id,
            integration_type = "AWS_PROXY",
            integration_uri = lambda_function_callback.function_arn,
            integration_method = "GET",
            payload_format_version = "2.0"
        )

        # API Gateway Lambda integration for token
        apigw_proxy_integration_token= _apigw.CfnIntegration(
            self, "ApiGwProxyIntegrationToken",
            api_id = apigw_proxy_api.attr_api_id,
            integration_type = "AWS_PROXY",
            integration_uri = lambda_function_token.function_arn,
            integration_method = "POST",
            payload_format_version = "2.0"
        )

        # Cloudwatch log group for API Gateway logs
        cloudwatch_apigw_proxy_log_group = _logs.LogGroup(
            self, "ApiGwLogs"
        )

        # API Gateway stage
        apigw_proxy_stage = _apigw.CfnStage(
            self, "ApiGwProxyStage",
            api_id = apigw_proxy_api.attr_api_id,
            stage_name = api_version,
            access_log_settings = _apigw.CfnStage.AccessLogSettingsProperty(
                destination_arn = cloudwatch_apigw_proxy_log_group.log_group_arn,
                format = (
                    '{'
                        '"requestId": "$context.requestId",'
                        '"path": "$context.path",'
                        '"routeKey": "$context.routeKey",'
                        '"ip": "$context.identity.sourceIp",'
                        '"requestTime": "$context.requestTime",'
                        '"httpMethod": "$context.httpMethod",'
                        '"statusCode": "$context.status"'
                    '}'
                )
            ),
            auto_deploy = True
        )

        # API Gateway route for authorization
        apigw_proxy_route_auth = _apigw.CfnRoute(
            self, "ApiGwProxyRouteAuth",
            api_id = apigw_proxy_api.attr_api_id,
            route_key = f"GET {authn_route}",
            target = "integrations/" + apigw_proxy_integration_auth.ref
        )
        apigw_proxy_route_auth_uri = apigw_proxy_api.attr_api_endpoint + "/" + apigw_proxy_stage.stage_name + authn_route

        # API Gateway authorization route Lambda invoke permission
        lambda_function_authorize.add_permission(
            "ApiGwAuthorizeRoutePermission",
            principal = _iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn = f"arn:aws:execute-api:{_aws.REGION}:{_aws.ACCOUNT_ID}:{apigw_proxy_api.ref}/*/*{authn_route}"
        )

        # API Gateway route for handling the IdP's callback
        apigw_proxy_route_callback = _apigw.CfnRoute(
            self, "ApiGwProxyRouteCallback",
            api_id = apigw_proxy_api.attr_api_id,
            route_key = f"GET {callb_route}",
            target = "integrations/" + apigw_proxy_integration_callback.ref
        )
        apigw_proxy_route_callb_uri = apigw_proxy_api.attr_api_endpoint + "/" + apigw_proxy_stage.stage_name + callb_route

        # API Gateway callback route Lambda invoke permission
        lambda_function_callback.add_permission(
            "ApiGwCallbackRoutePermission",
            principal = _iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn = f"arn:aws:execute-api:{_aws.REGION}:{_aws.ACCOUNT_ID}:{apigw_proxy_api.ref}/*/*{callb_route}"
        )

        # API Gateway route for token requests between Cognito and the IdP
        apigw_proxy_route_token = _apigw.CfnRoute(
            self, "ApiGwProxyRouteToken",
            api_id = apigw_proxy_api.attr_api_id,
            route_key = f"POST {token_route}",
            target = "integrations/" + apigw_proxy_integration_token.ref
        )
        apigw_proxy_route_token_uri = apigw_proxy_api.attr_api_endpoint + "/" + apigw_proxy_stage.stage_name + token_route

        # API Gateway callback route Lambda invoke permission
        lambda_function_token.add_permission(
            "ApiGwTokenRoutePermission",
            principal = _iam.ServicePrincipal("apigateway.amazonaws.com"),
            source_arn = f"arn:aws:execute-api:{_aws.REGION}:{_aws.ACCOUNT_ID}:{apigw_proxy_api.ref}/*/*{token_route}"
        )

        # API Gateway deployment definition
        apigw_proxy_deployment = _apigw.CfnDeployment(
            self, "ApiGwProxyDeployment",
            api_id = apigw_proxy_api.attr_api_id
        )
        apigw_proxy_deployment.add_dependency(apigw_proxy_route_auth)
        apigw_proxy_deployment.add_dependency(apigw_proxy_route_callback)
        apigw_proxy_deployment.add_dependency(apigw_proxy_route_token)

        # Translating list of scopes to cdk attributes
        cognito_oauth_scopes = []
        for scope in self.node.try_get_context("idp_scopes").split():
            if scope.lower() == "openid":
                cognito_oauth_scopes.append(_cognito.OAuthScope.OPENID)
            if scope.lower() == "email":
                cognito_oauth_scopes.append(_cognito.OAuthScope.EMAIL)
            if scope.lower() == "profile":
                cognito_oauth_scopes.append(_cognito.OAuthScope.PROFILE)
            if scope.lower() == "phone":
                cognito_oauth_scopes.append(_cognito.OAuthScope.PHONE)

        # Cognito User Pool base configuration
        cognito_user_pool = _cognito.UserPool(self, "UserPool")

        # Cognito external identity provider
        idp_issuer_url = self.node.try_get_context("idp_issuer_url")
        cognito_user_pool_idp_oidc = _cognito.UserPoolIdentityProviderOidc(
            self, "IdentityProvider",
            client_id = self.node.try_get_context("idp_client_id"),
            client_secret = self.node.try_get_context("idp_client_secret"),
            issuer_url = idp_issuer_url,
            user_pool = cognito_user_pool,
            attribute_request_method = _cognito.OidcAttributeRequestMethod.GET,
            endpoints = _cognito.OidcEndpoints(
                authorization = apigw_proxy_route_auth_uri,
                jwks_uri = idp_issuer_url + self.node.try_get_context("idp_keys_path"),
                token = apigw_proxy_route_token_uri,
                user_info = idp_issuer_url + self.node.try_get_context("idp_attributes_path")
            ),
            name = self.node.try_get_context("idp_name"),
            scopes = self.node.try_get_context("idp_scopes").split()
        )

        # Cognito Application Client
        cognito_user_pool_client = cognito_user_pool.add_client(
            "AppClient",
            o_auth = _cognito.OAuthSettings(
                flows = _cognito.OAuthFlows(
                    authorization_code_grant = True
                ),
                scopes = cognito_oauth_scopes,
                callback_urls = [self.node.try_get_context("userpool_allowed_callback_url")]
            ),
            supported_identity_providers = [_cognito.UserPoolClientIdentityProvider.custom(cognito_user_pool_idp_oidc.provider_name)]
        )

        # Cognito User Pool Domain for Hosted UI
        cognito_user_pool_domain = cognito_user_pool.add_domain(
            "CognitoDomain",
            cognito_domain = _cognito.CognitoDomainOptions(
                domain_prefix = apigw_proxy_api.attr_api_id
            )
        )


        """
        STACK OUTPUTS
        """

        _output(
            self, "ApiGwAuthnEndpoint",
            value = apigw_proxy_route_auth_uri
        )

        _output(
            self, "ApiGwCallbackEndpoint",
            value = apigw_proxy_route_callb_uri
        )

        _output(
            self, "ApiGwTokenEndpoint",
            value = apigw_proxy_route_token_uri
        )

        _output(
            self, "DynamoDbStateTable",
            value = dynamodb_state_table.table_name
        )

        _output(
            self, "DynamoDbCodeTable",
            value = dynamodb_code_table.table_name
        )

        _output(
            self, "SecretsManagerPrivateKeyArn",
            value = secretsmanager_private_key.secret_full_arn
        )

        _output(
            self, "SecretsManagerPrivateKeyName",
            value = secretsmanager_private_key.secret_name
        )

        _output(
            self, "CognitoHostedUi",
            value = cognito_user_pool_domain.base_url()
        )

        _output(
            self, "CognitoIdpResponseUri",
            value = cognito_user_pool_domain.base_url() + "/oauth2/idpresponse"
        )


        """
        SUPPRESSION RULES FOR CDK_NAG
        """

        NagSuppressions.add_resource_suppressions(
            secretsmanager_private_key, [
                { "id": "AwsSolutions-SMG4", "reason": "Cannot rotate due to 3rd party IdP dependency."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            lambda_function_authorize_exec_role, [
                { "id": "AwsSolutions-IAM4", "reason": "Demo purposes only." },
                { "id": "AwsSolutions-IAM5", "reason": "API is resource agnostic but resource key required in statement." },
            ]
        )


        NagSuppressions.add_resource_suppressions(
            lambda_function_callback_exec_role, [
                { "id": "AwsSolutions-IAM4", "reason": "Demo purposes only."}
            ]
        )


        NagSuppressions.add_resource_suppressions(
            lambda_function_token_exec_role, [
                { "id": "AwsSolutions-IAM4", "reason": "Demo purposes only."}
            ]
        )

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/Resource",
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "Construct specific: Enabling log retention creates a separate Lambda Function with managed policy."
                }
            ]
        )

        NagSuppressions.add_resource_suppressions_by_path(
            self,
            f"/{self.stack_name}/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/DefaultPolicy/Resource",
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Construct specific: Enabling log retention creates a separate Lambda Function with managed policy."
                }
            ]
        )

        NagSuppressions.add_resource_suppressions(
            lambda_function_authorize, [
                { "id": "AwsSolutions-L1", "reason": "No tests in place to guarantee code runs in other versions."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            lambda_function_callback, [
                { "id": "AwsSolutions-L1", "reason": "No tests in place to guarantee code runs in other versions."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            lambda_function_token, [
                { "id": "AwsSolutions-L1", "reason": "No tests in place to guarantee code runs in other versions."}
            ]
        )


        NagSuppressions.add_resource_suppressions(
            apigw_proxy_route_auth, [
                { "id": "AwsSolutions-APIG4", "reason": "Demo purposes only."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            apigw_proxy_route_callback, [
                { "id": "AwsSolutions-APIG4", "reason": "Demo purposes only."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            apigw_proxy_route_token, [
                { "id": "AwsSolutions-APIG4", "reason": "Demo purposes only."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            cognito_user_pool, [
                { "id": "AwsSolutions-COG1", "reason": "Demo is supposed to integrate only with external IdP."},
                { "id": "AwsSolutions-COG2", "reason": "Defined by external IdP."},
                { "id": "AwsSolutions-COG3", "reason": "Demo purposes only."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            dynamodb_state_table, [
                { "id": "AwsSolutions-DDB3", "reason": "Short lived data only."}
            ]
        )

        NagSuppressions.add_resource_suppressions(
            dynamodb_code_table, [
                { "id": "AwsSolutions-DDB3", "reason": "Short lived data only."}
            ]
        )
