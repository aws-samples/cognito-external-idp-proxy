# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import base64
import boto3
import hashlib
import json
import os
import re
import secrets
import string
import time
import urllib.parse


"""
Initializing SDK clients to facilitate reuse across executions
"""

SM_CLIENT = boto3.client('secretsmanager')
DYNAMODB_CLIENT = boto3.client("dynamodb")


def validate_request(params: dict) -> bool:
    """
    Helper function to validate request parameters - can be used to drop requests early during runtime.
    """
    validation = False

    if params["client_id"] == os.environ.get("ClientId"):
        validation = True

    return validation


def handler(event, context):
    print("+++ FULL EVENT DETAILS +++")
    print(event)

    # Collecting original request details
    params = event["queryStringParameters"]
    org_headers = event["headers"]

    # All print statements are left in to observe behaviour in CloudWatch
    print("+++ ORIGINAL REQUEST HEADER +++")
    print(org_headers)
    print("+++ ORIGINAL QUERY STRING PARAMs")
    print(event["queryStringParameters"])
    print("#####################")

    if not validate_request(params):
        print("+++ VALIDATION FAILED - CANCELLING +++")
        return { "statusCode": 400 }

    print("+++ VALIDATION SUCCESSFUL - PROCEEDING +++")

    # Collecting envvars and necessary original request parameters
    config = {}
    config["idp_auth_uri"] = os.environ.get("IdpAuthUri")
    config["proxy_callback_uri"] = os.environ.get("ProxyCallbackUri")
    config["state_table"] = os.environ.get("DynamoDbStateTable")

    print("+++ ENV VARS COLLECTED +++")
    print(config)

    # Generate code_verifier, hash it and remove padding
    code_verifier = SM_CLIENT.get_random_password(
        PasswordLength=64,
        ExcludePunctuation=True,
        IncludeSpace=False
    )
    code_verifier = code_verifier["RandomPassword"]

    code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    # store hashed state and code_verifier in dynamodb with ttl
    hashed_state = hashlib.sha256(params["state"].encode("utf-8")).hexdigest()
    print(f"Storing hashed state: {hashed_state}")
    state_ttl = int(time.time()) + 300
    DYNAMODB_CLIENT.put_item(
        TableName = config["state_table"],
        Item = {
            "state": {
                "S": str(hashed_state)
            },
            "code_verifier": {
                "S": code_verifier
            },
            "ttl": {
                "N": str(state_ttl)
            }
        }
    )

    # add code_challenge, code_challenge_method=S256 and proxy callback uri to params
    params["code_challenge"] = code_challenge
    params["code_challenge_method"] = "S256"
    params["redirect_uri"] = config["proxy_callback_uri"]

    print("+++ NEW QUERY STRING PARAMETERS +++")
    print(params)

    # call /authorize endpoint of the IdP with new params
    idp_redirect = config["idp_auth_uri"] + "?" + urllib.parse.urlencode(params)

    print("+++ REDIRECTING TO: +++")
    print(idp_redirect)

    # 302 to the IdP's authorize endpoint
    response_to_client = {}
    response_to_client["statusCode"] = 302

    response_to_client["body"] = json.dumps(dict())
    response_to_client["headers"] = {"Location": idp_redirect}

    return response_to_client
