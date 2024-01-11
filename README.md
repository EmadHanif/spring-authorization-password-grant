# Spring Authorization Server With OAuth 2.0 Password Grant Implementation


It's time to bid adieu to `spring-security-oauth2` and embrace the future with Spring Authorization Server. While aligning with the OAuth 2.1 draft specification, it's essential to note that Spring Authorization Server lacks built-in support for the password grant-type. For further details on OAuth 2.1, refer to this [link](https://www.miniorange.com/blog/what-is-oauth2-1-sso-protocol/). However, recognizing its significance, especially for direct integration with Angular/React/Vue, this repository offers a comprehensive template for implementing OAuth 2.0 password grant using Spring Authorization Server.

## Setup Instructions

### 1. Prerequisites

The repository requires Java 21, leveraging virtual threads, and Spring Boot 3.0.

### 2. Database Configuration

The implementation is configured with PostgreSQL. Ensure that the database configuration in `application-dev.properties` matches your setup:

```
config.database-config.host=jdbc:postgresql://localhost:5432/[DATABASE_NAME] 
config.database-config.username=postgres
config.database-config.password=[DB_PASSWORD]
```
Replace `[DATABASE_NAME]` and `[DB_PASSWORD]` with your database details.

### 3. Java KeyStore Configuration

Create a Java KeyStore file using the following command-line prompt, specifying alias, filename, and password:

```
keytool -genkeypair -alias "$alias" -keyalg RSA -keysize 2048 -keystore ${keystore-filename}.jks -storepass "$password" -validity 3650

```

Make relevant changes in `application.properties`.

```
jwt.keystore.jks-location=keystore/[JWK_FILE.jks]
jwt.keystore.keypair-alias=[JWK_ALIAS]
jwt.keystore.password=[JWK_PASSWORD]

```
Additionally, Spring Authorization Server provides the flexibility to configure the JWT keystore using base64 encoding, 


## Endpoints & Testing 

## 1. Available Endpoints
`POST /oauth2/token`: Generates access and refresh tokens.

`POST /oauth2/introspection`: Inspects access tokens.

`POST /oauth2/revoke`: Revokes access_tokens (consider custom logout implementation).

### 2. Testing

#### Generate Access token

```
curl --location --request POST 'http://localhost:8080/oauth2/token' \
--header 'Authorization: Basic c3ByaW5nLWFuZ3VsYXI6c3ByaW5nLWFuZ3VsYXItY2xpZW50LWtleQ==' \
--form 'grant_type="password"' \
--form 'username="david_freed@gmail.com"' \
--form 'password="adminadmin"'
```

#### Generate Refresh token

```
curl --location --request POST 'http://localhost:8080/oauth2/token' \
--header 'Authorization: Basic c3ByaW5nLWFuZ3VsYXI6c3ByaW5nLWFuZ3VsYXItY2xpZW50LWtleQ==' \
--form 'grant_type="refresh_token"' \
--form 'refresh_token="${your_refresh_token}"'
```

While this repository serves as an extensive Spring Security implementation template, it is crucial to highlight best practices. Particularly, the recommended practice is to handle `refresh_tokens` on the server-side and securely storing them as cookies.

#### Token introspection

```
curl --location --request POST 'http://localhost:8080/oauth2/introspect' \
--header 'Authorization: Basic c3ByaW5nLWFuZ3VsYXI6c3ByaW5nLWFuZ3VsYXItY2xpZW50LWtleQ==' \
--form 'token="${your_access_token}"'
```

## 🙏 Acknowledgement

Huge shootout to the Spring Team for redefining standards & pioneering advancements within the Java Ecosystem. 