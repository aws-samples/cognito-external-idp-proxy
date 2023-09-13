# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from botocore.exceptions import ClientError

import base64
import boto3
import http.client
import json
import jwt
import os
import pprint
import time
import urllib.parse


"""
Initializing SDK clients to facilitate reuse across executions
"""

DYNAMODB_CLIENT = boto3.client("dynamodb")

SM_CLIENT = boto3.client(
    service_name = "secretsmanager",
    region_name = os.environ.get("AWS_REGION")
)


def validate_request(params: dict) -> bool:
    """
    Helper function to validate request parameters - can be used to drop requests early during runtime.
    """
    validation = False

    if params["client_id"] == os.environ.get("ClientId") and params["client_secret"] == os.environ.get("ClientSecret"):
        validation = True

    return validation


def get_secret(secret_name):

    # Helper function to get secret from Secrets Manager

    try:
        get_secret_value_response = SM_CLIENT.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']

    return secret


def handler(event, context):
    #  All prints left in to observe behaviour in CloudWatch
    print("+++ FULL EVENT DETAILS +++")
    print(event)
    print("#####################")

    # Decode the cognito request and convert to utf-8
    encoded_message = event["body"]
    decoded_message = base64.b64decode(encoded_message)
    decoded_message = decoded_message.decode("utf-8")

    print("+++ DECODED COGNITO REQUEST +++")
    print(decoded_message)

    # Create parameter dictionary from request
    param_list = list(decoded_message.split("&"))
    param_dict = {}
    for item in param_list:
        key, value = item.split("=")
        param_dict[key] = value

    print("+++ DECODED PARAMETER LIST +++")
    print(param_dict)

    if not validate_request(param_dict):
        print("+++ VALIDATION FAILED - CANCELLING +++")
        return { "statusCode": 400 }

    print("+++ VALIDATION SUCCESSFUL - PROCEEDING +++")

    # Defining pkce toggle here because it is required in multiple different parts below
    pkce_toggle = False

    if os.environ.get("Pkce").lower() == "true":
        pkce_toggle = True
        print("+++ USING PKCE +++")

    # Fetching all details from original request and env vars
    config = {}
    config["auth_code"] = param_dict["code"]
    config["client_id"] = param_dict["client_id"]
    config["idp_issuer_url"] = os.environ.get("IdpIssuerUrl")
    config["idp_token_path"] = os.environ.get("IdpTokenPath")
    config["idp_token_endpoint"] = config["idp_issuer_url"] + config["idp_token_path"]
    config["secret_name"] = os.environ.get("SecretsManagerPrivateKey")
    config["original_response_uri"] = os.environ.get("ResponseUri")

    if pkce_toggle:
        config["code_table"] = os.environ.get("DynamoDbCodeTable")

    print("+++ CONFIGURATION ITEMS +++")
    print(config)

    # Get code_verifier associated with auth_token when using PKCE
    if pkce_toggle:
        code_result = DYNAMODB_CLIENT.get_item(
            TableName = config["code_table"],
            Key = {
                "auth_code": {
                    "S": config["auth_code"]
                }
            }
        )
        code_verifier = code_result["Item"]["code_verifier"]["S"]

        print("+++ CODE VERIFIER FOUND +++")
        print(code_verifier)

    # Get private key from Secrets Manager
    print("+++ RETRIEVING SECRET FROM SECRET MANAGER +++")
    private_key = get_secret(config["secret_name"])
    private_key_dict = json.loads(private_key)
    private_key = jwt.jwk_from_dict(private_key_dict)
    print("+++ KEY RETRIEVED +++")

    print("+++ SIGNING TOKEN +++")
    # Create the private key jwt
    instance = jwt.JWT()
    private_key_jwt = instance.encode({
        "iss": config["client_id"],
        "sub": config["client_id"],
        "aud": config["idp_token_endpoint"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 300
    },
        private_key,
        alg='RS256',
        optional_headers = {"kid": private_key_dict["kid"]}
    )

    print("+++ PRIVATE KEY JWT +++")
    print(private_key_jwt)

    # Add client_assertion to the query string params
    param_dict["client_assertion"] = private_key_jwt
    param_dict["grant_type"] = "authorization_code"
    param_dict["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    param_dict["redirect_uri"] = config["original_response_uri"]

    # Add the api gw url from the authorize request and code verifier when using PKCE
    if pkce_toggle:
        param_dict["code_verifier"] = code_verifier

    # Removing because it is not needed
    param_dict.pop("client_secret")

    # Make the token request
    clean_url = config["idp_issuer_url"][8:]
    conn = http.client.HTTPSConnection(clean_url)

    payload = urllib.parse.urlencode(param_dict)
    print("+++ PAYLOAD +++")
    print(payload)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    conn.request('POST', f'{config["idp_token_path"]}', payload, headers)
    res = conn.getresponse()

    print("+++ IDP RESPONSE +++")
    print(f"Status: {res.status}, Reason {res.reason}")

    # Return IdP response to Cognito
    data = res.read().decode("utf-8")

    print(data)

    return data

