# Spring Authorization Server With OAuth 2.0 Password Grant Implementation

As `spring-security-oauth2` reached end-of-life in 2022, Spring Authorization Server represents the modern approach for OAuth 2.x implementation. While aligning with the OAuth 2.1 draft specification, Spring Authorization Server doesn't provide built-in support for the password grant type. For more context, see the [OAuth 2.1 specification](https://www.miniorange.com/blog/what-is-oauth2-1-sso-protocol/).

The password grant flow remains widely used in real-world scenarios, particularly for direct integration with modern frontend frameworks like Angular, React and Vue. This repository provides a comprehensive template for implementing OAuth 2.0 password grant authentication using Spring Authorization Server.

## Setup Instructions

### Database Configuration

This project uses PostgreSQL. Update your database configuration in `application-dev.properties` to match your environment:

```properties
config.database-config.host=jdbc:postgresql://localhost:5432/[DATABASE_NAME]
config.database-config.username=postgres
config.database-config.password=[DATABASE_PASSWORD]
```

Replace `[DATABASE_NAME]` and `[DATABASE_PASSWORD]` with your database credentials.

#### Database Schema Setup

1. Create your database in PostgreSQL.
2. Initialize the schema by executing the provided SQL script: `src/main/resources/schema/create-oauth2.sql`

#### Using MySQL Instead of PostgreSQL:

If you're using MySQL, apply the following changes to the schema file before execution:
- Replace all `text` data types with `blob`
- Replace all `timestamptz` data types with `timestamp`

### Java KeyStore Configuration

**Note:** A default keystore is already embedded in this repository. This section is for reference only if you wish to generate your own keystore.

To generate a Java Keystore file for signing JWT, use the following command with your own values:

```
keytool -genkeypair -alias myalias -keyalg RSA -keysize 2048 -keystore mykeystore.jks -storepass mypassword -validity 3650
```

After generating the keystore, update the following properties in `application.properties`:

```
jwt.keystore.jks-location=keystore/[JWK_FILE].jks
jwt.keystore.keypair-alias=[JWK_ALIAS]
jwt.keystore.password=[JWK_PASSWORD]
```

Spring Authorization Server also supports base64-encoded keystore configuration.

### API Endpoints

The following OAuth 2.0 endpoints are available:

- **POST /oauth2/token:** Generates access and refresh tokens
- **POST /oauth2/introspect:** Validates and inspects access tokens
- **POST /oauth2/revoke:** Revokes token *(Implements your own custom logout endpoint to remove token from the database and clear refresh token cookie)*

## Usage Examples

### Generate Access Token

```bash
curl --request POST \
  --url http://localhost:8080/oauth2/token \
  --header 'authorization: Basic Y2xpZW50OnNlY3JldA==' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=password \
  --data username=david_freed@gmail.com \
  --data password=adminadmin \
  --data scope=user
```

### Generate Refresh Token


```bash
curl --request POST \
  --url http://localhost:8080/oauth2/token \
  --header 'authorization: Basic Y2xpZW50OnNlY3JldA==' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data grant_type=refresh_token \
  --data refresh_token={{refresh_token}}
```

**Best Practice:** Handle refresh tokens server-side and store them securely in HTTP-only cookies after successful authentication.

### Introspect Token

```bash
curl --request POST \
  --url http://localhost:8080/oauth2/introspect \
  --header 'authorization: Basic Y2xpZW50OnNlY3JldA==' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data token={{access_token}}
```

## Test Protected Endpoints

### Public endpoint (No Authentication Required):
```bash
curl --request GET \
  --url http://localhost:8080/api/v1/example/m1
```

`m1()` is a publicly exposed endpoint.

### Protected Endpoint:
```bash
curl --request GET \
  --url http://localhost:8080/api/v1/example/m2 \
  --header 'authorization: Bearer {{access_token}}'
```

Requires a valid access token with scope `user` and role `ROLE_ADMIN`.

### Protected Reactive Endpoint:
```bash
curl --request GET \
  --url http://localhost:8080/api/v1/example/m3 \
  --header 'authorization: Bearer {{access_token}}'
```

`m3()` is a reactive endpoint that returns RxJava `Single`, demonstrating reactive execution within an OAuth 2.0 secured context. Also requires a valid access token with scope `user` and role `ROLE_ADMIN`.

## Acknowledgement

Special thanks to the Spring Team for redefining standards and pioneering advancements within the Java ecosystem.

