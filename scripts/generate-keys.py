# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from jwcrypto import jwk

import os
import uuid

# Defining output filenames for keys
pbkey_name = "public_key.json"
prkey_name = "private_key.json"
key_dir = "local"

# Create a random string as key identifier
keyid = str(uuid.uuid4())

# Generate key material for public anc private key as JWK
key = jwk.JWK.generate(kty="RSA", size=4096, kid=keyid)
public_key = key.export_public()
private_key = key.export_private()

# Store key to local filesystem and print output for quick reference
try:
    os.mkdir(key_dir)

except FileExistsError:
    print("Directory exists - using that.")

except:
    raise


try:
    with open(f"{key_dir}/{pbkey_name}", "w") as pbk:
        pbk.write(public_key)

    print("\n\n### PUBLIC KEY TO PASTE IN IDP ###\n")
    print(public_key)

    with open(f"{key_dir}/{prkey_name}", "w") as prk:
        prk.write(private_key)

    print("\n\n### PRIVATE KEY! STORE SECURELY! ###\n")
    print(private_key)

except:
    raise

finally:
    print(f"\n\nKey files generated: {key_dir}/{pbkey_name}, {key_dir}/{prkey_name}")
