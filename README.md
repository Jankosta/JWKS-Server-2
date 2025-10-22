# JWKS Server

A simple JSON Web Key Set (JWKS) and authentication server built with **Node.js** and **Express**.  
This project demonstrates how to serve JWKS for verifying JSON Web Tokens (JWTs) and how to issue tokens signed by the server's keys.

---

## Features

- **JWKS Endpoint** – Serves public keys for JWT verification.
- **Auth Endpoint** – Issues signed JWTs using an unexpired key.
- **Expired Key Support** – Optionally issues expired tokens for testing.
- **Health Check** – Quick endpoint to verify the server is running.
- **Comprehensive Tests** – Includes unit and integration tests for endpoints.
- **Linting** – Enforces code style via ESLint.

---

## Endpoints

### `GET /.well-known/jwks.json`

Returns the JSON Web Key Set.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-123",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### `GET /jwks`

Alias of the above endpoint.

### `POST /auth`

Returns a signed JWT using a valid, unexpired key.

**Example response:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6..."
}
```

### `POST /auth?expired=1`

Returns a signed JWT using an expired key (for testing).

### `GET /health`

Health check endpoint. Returns:

```json
{
  "status": "ok"
}
```

---

## Installation & Setup

1. Clone this repository:

   ```bash
   git clone https://github.com/your-username/jwks-server.git
   cd jwks-server
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Run the server:
   ```bash
   npm start
   ```

The server will start on [http://localhost:8080](http://localhost:8080).

---

## Development

Lint code with ESLint:

```bash
npm run lint
```

Run test suite:

```bash
npm test
```

---

## Project Structure

```
src/
  index.js       # App setup and routes
  handlers.js    # Route handlers
  keystore.js    # Key management
tests/
  auth.test.js   # Tests for /auth
  index.test.js  # Tests for app setup and routes
  jwks.test.js   # Tests for /jwks
```

---

## References

- [HTTP](https://en.wikipedia.org/wiki/HTTP)
- [REST](https://en.wikipedia.org/wiki/REST)
- [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token)
- [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/rfc7517/)

---

## Acknowledgments

- Assistance was received from **Copilot** to aid in development of this project, particularly in setting up testing and linting. **Copilot** was used for error handling, offering suggestions and fixes whenever I could not locate the origin or solution to an issue. My mindset was first to see if I could solve the issue on my own, before then moving to ask AI for the root cause of the error and an explanation of how to fix it and how to avoid such issues in the future.
- Assistance was received from **ChatGPT** in regards to README formatting and review. **ChatGPT** was also utilized to suggest a file layout/skeleton for the project, suggesting what contents should be located in each file. It was additionally used in the initial setup phase in regards to installing the necessary packages. The prompts involved providing the AI with the assignment description as well as my personal goals for the project, asking it to suggest a clean and effective project skeleton. An example of such a prompt is as follows: "I have an assignment to create a simple JWKS server using Node.js and Express. Can you suggest a clean project skeleton, including which files I should create (e.g., index.js, routes/, tests/) and what each should contain? Here is the project description: (Simplified Project Description)"
