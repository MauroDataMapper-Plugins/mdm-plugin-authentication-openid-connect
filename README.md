# mdm-plugin-authentication-openid-connect

| Branch | Build Status |
| ------ | ------------ |
| master | [![Build Status](https://jenkins.cs.ox.ac.uk/buildStatus/icon?job=Mauro+Data+Mapper+Plugins%2Fmdm-plugin-authentication-openid-connect%2Fmaster)](https://jenkins.cs.ox.ac.uk/blue/organizations/jenkins/Mauro%20Data%20Mapper%20Plugins%2Fmdm-plugin-authentication-openid-connect/branches) |
| develop | [![Build Status](https://jenkins.cs.ox.ac.uk/buildStatus/icon?job=Mauro+Data+Mapper+Plugins%2Fmdm-plugin-authentication-openid-connect%2Fdevelop)](https://jenkins.cs.ox.ac.uk/blue/organizations/jenkins/Mauro%20Data%20Mapper%20Plugins%2Fmdm-plugin-authentication-openid-connect/branches) |

## Requirements

* Java 17 (Temurin)
* Grails 5.1.9+
* Gradle 7.3.3+

All of the above can be installed and easily maintained by using [SDKMAN!](https://sdkman.io/install).

## Applying the Plugin

The preferred way of running Mauro Data Mapper is using the [mdm-docker](https://github.com/MauroDataMapper/mdm-docker) deployment. However you can
also run the backend on its own from [mdm-application-build](https://github.com/MauroDataMapper/mdm-application-build).

### mdm-docker

In the `docker-compose.yml` file add:

```yml
mauro-data-mapper:
    build:
        args:
            ADDITIONAL_PLUGINS: "uk.ac.ox.softeng.maurodatamapper.plugins:mdm-plugin-authentication-openid-connect:2.2.0"
```

Please note, if adding more than one plugin, this is a semicolon-separated list

### mdm-application-build

In the `build.gradle` file add:

```groovy
grails {
    plugins {
        runtimeOnly 'uk.ac.ox.softeng.maurodatamapper.plugins:mdm-plugin-authentication-openid-connect:2.2.0'
    }
}
```

## Workflow

### Authentication Workflow
Described by https://auth0.com/docs/flows/authorization-code-flow

1. UI requests known providers from us
2. User clicks link provided by UI
   * UI has to add the `redirect_uri` url param to the url
3. User is taken to authentication request url
4. User authenticates
5. Auth returns response with params in url
    * session_state 
    * code 
    * state 
6. UI sends these params to API as the body of a login request
    * session_state
    * code
    * state
    * redirect_uri = exact uri used by UI
7. API calls the access token endpoint using these parameters as a urlencoded form post 
   (also use basic auth header with username: `client_secret`,password: `$clientSecret`)
    * client_id
    * client_secret
    * grant_type
    * code
    * redirect_uri
    * session_state
8. Response back in JSON form
    * access_token
    * expires_in
    * refresh_expires_in
    * token_type
    * id_token
    * not-before-policy
    * session_state
    * scope
9. API verifies the id_token which is a JWT
10. API retrieves userinfo to create user if one does not exist, otherwise grabs user for the email
11. API stores the token data into the database?
    

## Access Workflow

1. Every subsequent API call is interecepted and the token is checked to ensure the access_token is still valid
   * Done by checking "now" vs decodedjwt "getExpiresAt"
   * access tokens are not always JWT, they are provider specific, so we treat them as coded strings as we dont want to rely on functionality which may not be there  
2. If expired then we check for a refresh token and if that has expired
3. If refresh token and not expired then we call for a new access token and update whats stored
4. If no refresh token or expired then we invalidate the session and return


## Security 

### State

State is there to protect the end user from cross site request forgery(CSRF) attacks. It is introduced from OAuth 2.0 protocol RFC6749. Protocol states that:


> Once authorization has been obtained from the end-user, the authorization server redirects the end-user's user-agent back to the client with the required 
> binding value contained in the "state" parameter. The binding value enables the client to verify the validity of the request by matching the binding value 
> to the user-agent's authenticated state

This is therefore a UI communication thing which the API can supply as a random UUID.

> An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user-agent 
> back to the client. The parameter SHOULD be used for preventing cross-site request forgery

### Nonce

Nonce serves a different purpose. It binds the tokens with the client. It serves as a token validation parameter and is introduced from OpenID Connect specification.

> String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value is passed through unmodified from the 
> Authentication Request to the ID Token. If present in the ID Token, Clients MUST verify that the nonce Claim Value is equal to the value of the nonce 
> parameter sent in the Authentication Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID 
> Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD perform no other processing on nonce 
> values used. The nonce value is a case sensitive string

Nonce is therefore an API thing which the API will generate cryptographically from the session id. Therefore no 2 sessions will have the same nonce
and it will be impossible to guess or fake as the session id cannot be manually configured.

> The nonce parameter value needs to include per-session state and be unguessable to attackers. One method to achieve this for Web Server Clients is to 
> store a cryptographically random value as an HttpOnly session cookie and use a cryptographic hash of the value as the nonce parameter. In that case, 
> the nonce in the returned ID Token is compared to the hash of the session cookie to detect ID Token replay by third parties. A related method 
> applicable to JavaScript Clients is to store the cryptographically random value in HTML5 local storage and use a cryptographic hash of this value.

## Notes:

The API supplies all of the authentication url prebuilt and requires the UI to add the `redirect_uri` parameter

### Openid Connect Specifications

#### Authorisation Endpoint

https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

#### Access Token Endpoint

https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

A failed attempt will nullify the code returned by the UI, requiring a request for a new code

#### User Information Endpoint

https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

#### Client Authentication

https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

### Provider Specific Documentation

#### Keycloak Documentation

https://www.keycloak.org/docs/latest/securing_apps/index.html#endpoints

#### Google Documentation

https://developers.google.com/identity/protocols/oauth2/openid-connect

Note that refresh token is not sent as the access token has a 51min expiry life and therefore is unlikely to be needed.
I believe that making any access check request "resets" the expiry counter but this will need to be checked
It may also be the same for Keycloak with the "reset"

## Development - Mauro and Secure Data Environment (SDE) Keycloak Setup
The following instructions are for configuring a development environment to use a local Keycloak server with Mauro and the Secure Data Environment (SDE). These instructions are based on all Mauro and SDE web applications running on their default port numbers.

### Setup Keycloak Server
https://www.keycloak.org/downloads.html <br>
Download the Server keycloak

Unzip the keycloak file to a local folder. Then go to the `bin` folder. e.g: <br>
`cd E:\keycloak-24.0.4\bin`

Run key cloak with this command. We want to keep it out of the way of mauro and SDE port numbers so put it on 9009: <br>
`kc --verbose start-dev --debug 5050 --http-port 9009`

Open a web browser and go to: http://localhost:9009/ <br>

If everything is working as it should be you will be prompted to create a Keycloak administrator account. Create the account. Once created you should be logged into Keycloak and ready to go.

### Setup Mauro client in Keycloak
Log in to Keycloak as an Administrator <br>

Click on Clients in the main menu on the left (Click the three horizontal lines icon if menu not visible) <br>

Click "Create client" button <br>
- ClientID: Mauro
- Name: Mauro
- Description: Mauro and SDE <br>

Click "Next"
- Client Authentication: On <br>

Click "Next" <br>

- Root URL: `http://localhost:4200`
- Home URL: `http://localhost:4200/redirects/open-id-connect-redirect.html`
- Valid redirectURIs:<br>
`http://localhost:4200/redirects/open-id-connect-redirect.html` <br>
`http://localhost:4201/redirects/open-id-connect-redirect.html` <br>
`http://localhost:8082/oauth/callback/keycloak` <br>
`http://localhost:8081/oauth/callback/keycloak`
- Web origins: `http://localhost:4200`
- Admin URL: `http://localhost:4200` <br>

Click "Save"

### Configure Mauro to use Keycloak
Log in to Mauro as an administrator (Use a direct login, NOT an Open ID login)

On the user menu select "Open ID Connect"

Click on "Add"
- Label: Keycloak (This exact wording must be used for the label to link the Mauro and SDE login processing)
- Image URL: `https://upload.wikimedia.org/wikipedia/commons/2/29/Keycloak_Logo.png?20200311211229`
- Client ID: Mauro
- Client Secret: This can be found in Keycloak server by selecting the Mauro client and going to the Credentials tab. Copy the Client Secret and paste it here.
- Use discovery document for endpoints: True (Ticked)
- Discovery document URL: `http://localhost:9009/realms/master/.well-known/openid-configuration`

Click "Add Provider"
 

### Configure SDE to use Keycloak
The Open ID connect configuration has to be setup in configuration files that are read when the SDE starts.

In your local checkout of the SDE go to folder `../sde-core/.run`

Edit file `sde-core_admin-api [run].run.xml` and add the following:
```
<entry key="OAUTH_KEYCLOAK_ENABLED" value="true" />
<entry key="OAUTH_KEYCLOAK_CLIENT_ID" value="Mauro" />
<entry key="OAUTH_KEYCLOAK_CLIENT_SECRET" value="the client secret" />
<entry key="OAUTH_KEYCLOAK_ISSUER_URL" value="http://localhost:9009/realms/master" />
```
"the client secret" can be found in Keycloak server by selecting the Mauro client and going to the Credentials tab. Copy the Client Secret and paste it here.

Save the changes.

Edit file `sde-core_researcher-api [run].run.xml` and update it in exactly the same way as the `sde-core_admin-api [run].run.xml` that you just updated.
  
Save the changes.

Restart `admin-api` and `researcher-api` applications

## Create Users
Only researchers need to have an account in Mauro. You don't need to setup any users in the SDE as these will be automatically created the first time the user logs in.

### Create a Research User in Mauro
On the user menu select "Manage Users"
Click "Add"
Fill in all mandatory fields and set "Choose a Group" to "Explorer Readers". e.g:
- Email: researcher.one@sdetest.com
- First name: Researcher
- Last name: One
- Choose a Group: Explorer Readers

### Create Admin and Research Users in Keycloak
Log in to Keycloak Server as an Administrator. ( http://localhost:9009/ )

#### Research User
First setup a research user. The email address needs to match the one that you setup in Mauro.

Click on "Users" in the menu on the left

Click on "Add user"
- Email verified: Yes
- Username: researcher_one
- Email: researcher.one@sdetest.com
- First name: Researcher
- Last name: One

Click "Create"

You should now be on a "User details" page for the user you just created.

Click on "Credentials" tab
Click on "Set password"
- Password: password
- Password confirmation: password
- Temporary: Off

Click "Save"

Click "Save password"

#### Admin User
Now create an Admin account

Click on "Users" in the menu on the left

Click on "Add user"
- Email verified: Yes
- Username: admin_one
- Email: admin.one@sdetest.com
- First name: Admin
- Last name: One

Click "Create"

You should now be on a "User details" page for the user you just created.

Click on "Credentials" tab
Click on "Set password"
- Password: password
- Password confirmation: password
- Temporary: Off

Click "Save"

Click "Save password"

### Test logging in to Mauro UI
Make sure you have Mauro up and running. i.e:
- mdm-core
- mdm-ui

In a web browser go to: http://localhost:4200

Click on "Log in"

You should see a "Keycloak" button. Click it.

When prompted sign in as Researcher One.
- username: researcher_one
- password: password

If everything is setup correctly then you should now be logged into Mauro.

### Test logging in to SDE Admin
Make sure you have SDE Admin up and running. i.e:
- admin-api (sde-core)
- sde-admin-ui

In a web browser go to: http://localhost:4202

Click on "Log in"

You should see a "Sign in with Keycloak" button. Click it.

When prompted sign in as Researcher One.
- username: admin_one
- password: password

If everything is setup correctly then you should now be logged into the SDE.

### Test logging in to Mauro Data Explorer (MDE)
Make sure you have MDE up and running. i.e:
- mdm-core
- researcher-api (sde-core)
- mdm-explorer

Make sure you are logged out of Keycloak. This is important, because if you are logged in as an SDE administrator you won't be able to login to the MDE. You may need to clear your cookies to achieve this.

In a web browser go to: http://localhost:4201

Click on "Sign in"

You should see a "Sign in with Keycloak" button. Click it.

When prompted sign in as Researcher One.
- username: researcher_one
- password: password

If everything is setup correctly then you should now be logged into the MDE.

Click on the "SDE" tab in the top bar. This should load the Secure Data Environment page with no errors. 
