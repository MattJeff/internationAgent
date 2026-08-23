# Agent Employee OS — Rust

Production-oriented foundation for creating an AI employee with identity, communications, wallet, browser, vault, company knowledge, MCP, A2A and policy-controlled actions.

## Run the starter

```bash
docker compose up -d
cargo run -p agentos-api
```

Create an employee:

```bash
curl -X POST http://localhost:8080/v1/employees \
  -H 'content-type: application/json' \
  -d '{
    "tenant_id":"018f4f5a-7b43-7f41-b1fa-2ef54c2e8d15",
    "display_name":"Lena",
    "slug":"lena",
    "role":"international_buyer",
    "objective":"Source qualified suppliers worldwide"
  }'
```

The demo adapters deliberately return `pending_external` for phone and WhatsApp to model real provider/compliance behavior.

See `SPEC.md` for the complete production specification.
