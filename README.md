# 🧠 MCP PID Wallet Verifier

A lightweight and AI-friendly **MCP server** that allows any **AI agent** or **MCP-compatible assistant** to initiate and verify a **PID (Personal Identity Data) credential presentation** via **OIDC4VP**.

This server is designed to support **secure, QR-based wallet interactions** and can be used with agents like [Cline](https://cline.bot), OpenAI’s GPTs (via custom tools), or any custom client following the MCP protocol.

---

## 🚀 Features

- ✅ Supports **OIDC4VP Draft-13** with `direct_post` response mode
- ✅ Two-step **MCP REST tools** for credential presentation
- ✅ Generates **QR codes** and openid-vc:// deep links
- ✅ Receives **SD-JWT-based credentials** from EUDI-compatible wallets
- ✅ Stateless via **Redis** session storage
- ✅ Fully MCP-compliant via `.well-known/mcp/tools`

---

## 🔧 Tools Exposed (MCP REST)

### `1. initiate_pid_request`

Start an OIDC4VP presentation flow. Returns a QR code and session ID.

**POST** `/tools/initiate_pid_request`

#### Response

```json
{
  "status": "pending",
  "instructions": "Scan this QR code with your wallet to present a credential.",
  "session_id": "f1203ea7-d5...",
  "presentation_url": "openid-vc://?client_id=...",
  "qr_code_base64": "data:image/png;base64,..."
}
```

---

### `2. check_pid_result`

Poll the status of the credential presentation.

**POST** `/tools/check_pid_result`

#### Request

```json
{
  "session_id": "f1203ea7-d5..."
}
```

#### Possible Responses

- Pending:

```json
{ "status": "pending" }
```

- Verified:

```json
{
  "status": "verified",
  "verified_credential": {
    "given_name": "Jean",
    "family_name": "Dupont",
    "birth_date": "1975-06-23"
  }
}
```

- Error:

```json
{ "status": "error" }
```

---

## 🧠 Use Case

This server enables an AI agent to:
1. Ask a user to present their digital ID (PID)
2. Show them a scannable QR code
3. Wait for wallet response via OIDC4VP
4. Extract and use verified attributes (e.g., name, birth date)

Perfect for use in:
- Identity verification flows
- Onboarding
- Compliance & KYC automation
- Government-grade AI applications

---

## 🛠️ Tech Stack

- Python + Flask
- Redis for session handling
- `jwcrypto` for JWT signing/verification
- `qrcode` for base64-encoded QR image generation
- Compatible with EUDI-compliant wallets and SD-JWT

---

## 🌍 Deployment

Can be hosted easily via:
- [Render](https://render.com)
- [Fly.io](https://fly.io)
- [Railway](https://railway.app)
- Docker / VPS

> Be sure to expose `/.well-known/mcp/tools` to ensure discoverability by clients.

---

## 📄 MCP Tool Discovery

**GET** `/.well-known/mcp/tools`

Returns a JSON manifest describing available tools, input schema, and descriptions.

---

## 🧪 Demo Agent Available

You can test this server using a local or scripted agent that calls:
- `/tools/initiate_pid_request`
- `/tools/check_pid_result`

Or use a Custom GPT / Claude with support for MCP tools.

---

## 🛡️ Security Notes

- Temporary data is stored with expiration (`setex`)
- Signature verification via `verif_token()`
- Expiration (`exp`) and nonce handling included
- Designed for secure, audit-friendly digital identity operations

---

## 📬 Contact

Created by [Talao](https://talao.io)  
Maintainer: thierry.thevenet@talao.io  
License: MIT
