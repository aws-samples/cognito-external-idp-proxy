# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import boto3
import hashlib
import json
import os
import time
import urllib.parse


"""
Initializing SDK clients to facilitate reuse across executions
"""

DYNAMODB_CLIENT = boto3.client("dynamodb")


def validate_request(params: dict) -> bool:
    """
    Helper function to validate request parameters - can be used to drop requests early during runtime.
    """
    validation = False

    if params["state"] and params["code"]:
        validation = True

    return validation


def handler(event, context):
    #  All prints left in to observe behaviour in CloudWatch
    print("+++ FULL EVENT DETAILS +++")
    print(event)

    print("+++ ORIGINAL REQUEST HEADER +++")
    org_headers = event["headers"]
    print(org_headers)

    print("+++ ORIGINAL QUERY STRING PARAMs")
    org_params = event["queryStringParameters"]
    print(org_params)
    print("#####################")

    if not validate_request(org_params):
        print("+++ VALIDATION FAILED - CANCELLING +++")
        return { "statusCode": 400 }

    print("+++ VALIDATION SUCCESSFUL - PROCEEDING +++")

    # Collecting details from env vars and query string parameters
    config = {}
    config["auth_code"] = org_params["code"]
    config["state"] = org_params["state"]
    config["auth_code_table"] = os.environ.get("DynamoDbCodeTable")
    config["state_table"] = os.environ.get("DynamoDbStateTable")
    config["cognito_idp_response_uri"] = os.environ.get("CognitoIdpResponseUri")

    print("+++ CONFIGURATION ITEMS +++")
    print(config)

    # Get code_verifier from state_table with hashed state
    hashed_state = hashlib.sha256(config["state"].encode("utf-8")).hexdigest()
    print(f"Looking for state hash: {hashed_state}")
    state_result = DYNAMODB_CLIENT.get_item(
        TableName = config["state_table"],
        Key = {
            "state": {
                "S": str(hashed_state)
            }
        }
    )

    code_verifier = state_result["Item"]["code_verifier"]["S"]

    print("+++ CODE VERIFIER FOUND +++")
    print(code_verifier)

    # Store auth_code and code_verifier in auth_code_table
    code_ttl = int(time.time()) + 300
    DYNAMODB_CLIENT.put_item(
        TableName = config["auth_code_table"],
        Item = {
            "auth_code": {
                "S": config["auth_code"]
            },
            "code_verifier": {
                "S": code_verifier
            },
            "ttl": {
                "N": str(code_ttl)
            }
        }
    )

    # Switch URL to Cognito IdP response URL and attach original query string parameters
    cognito_redirect_url = config["cognito_idp_response_uri"] + "?" + urllib.parse.urlencode(org_params)
    redirect_to_cognito = {}
    redirect_to_cognito["statusCode"] = 302
    redirect_to_cognito["body"] = json.dumps(dict())
    redirect_to_cognito["headers"] = {"Location": cognito_redirect_url}

    print("+++ CRAFTING REDIRECT TO COGNITO +++")
    print(redirect_to_cognito)

    return redirect_to_cognito
