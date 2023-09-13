# How to setup Okta with Private Key JWT and PKCE

If you want to follow along with the solution in this sample but do not have an existing IdP, you can create one with Otka.

If you are already using Okta, directly jump to the [Create an OIDC application](#create-an-oidc-application) section down below.

To retrieve the OIDC endpoints for the stack configuration, jump to the [Retrieve OIDC endpoints](#retrieve-oidc-endpoints)

## Open a developer account
Okta offers free developer accounts that let you use it as an IdP in this sample. Sign up [here](https://developer.okta.com/signup/)

## Create an OIDC application
* After loging in to your Okta admin portal, navigate to Applications > Applications in the menu and select "Create App integration".

![Screenshot of the Application section in the Okta admin portal](docs/assets/images/okta-applications-1.png)

* In the opening dialogue, select "OIDC - OpenID Connect" as the Sign-in method an "Web Application" as the application type.

![Screenshot of the Okta app integration dialogue](docs/assets/images/okta-applications-2.png)

* After hitting next, you can give your integration a name and need to provide the API Gateway /callback route URI under the Sign-in redirect URIs. You can get the value from the output of the stack deployment. Alternatively, leave the placeholder value and come back later.

![Screenshot of the Okta app integration configuration dialogue](docs/assets/images/okta-applications-3.png)

* Under Assignments, select "Allow everyone in your organization to access" and leave the "Federation Broker" Mode enabled. If you are using your existing Okta account, consider to select "Limit acces to selected groups" and make sure to assign the correct groups of your directory.

![Screenshot of the Okta app integration configuration assignment section](docs/assets/images/okta-applications-4.png)

* Hit save to finish the initialization. You are redirected to the application integration overview. Select your newly created application and proceed with the next steps.

## Activate Private Key JWT and PKCE functionality
* In the general settings of your application integration settings, click the edit button of the "Client Credentials" settings. Then select "Public key / Private key" as Client authentication and "Require PKCE as additional verification". Leave the rest as is. Hit "Save" to confirm the configuration.

![Screenshot of the Okta app integration configuration with Private Key JWT and PKCE](docs/assets/images/okta-applications-5.png)

## Integrate a key pair
* After activating Private Key JWT and PKCE for your application integration, you can add public keys to it.

![Screenshot of the Okta app integration public key section](/docs/assets/images/okta-applications-6.png)

* You have the option to let Okta create both keys for you, by selecting "Generate new key". Make sure to copy the private key section and securely store it.

![Screenshot of an Okta created key pair](/docs/assets/images/okta-applications-7.png)

* Or, you can generate keys with the provided [script in this repository](../README.md#user-content-create-a-private-public-key-pair-in-jwk-format) (2. Option) and just upload the public key.

![Screenshot of providing your own public key](/docs/assets/images/okta-applications-8.png)

## Retrieve OIDC endpoints
All necessary endpoints are listed under `https://<your-okta-domain>.okta.com/.well-known/openid-configuration`. A populated cdk.context.json for stack deployment looks like this:

```json
{
  "api_version": "v1",
  "api_authn_route": "/authorize",
  "api_callback_route": "/callback",
  "api_token_route": "/token",
  "idp_attributes_path": "/oauth2/v1/userinfo",
  "idp_auth_path": "/oauth2/v1/authorize",
  "idp_keys_path": "/oauth2/v1/keys",
  "idp_token_path": "/oauth2/v1/token",
  "idp_client_id": "YOUR CLIENT ID",
  "idp_client_secret": "OPTIONAL",
  "idp_issuer_url": "https://<your-okta-domain>.okta.com",
  "idp_name": "Okta",
  "idp_scopes": "openid email profile",
  "pkce": true,
  "userpool_allowed_callback_url": "YOUR APPLICATION URL or https://localhost for testing"
}
```
