# Dynamic Token Generator and Parser

This project implements a generator and parser for a dynamic token format based on ASN.1/DER structure, as reverse‑engineered from a sample token.

## Token Structure

The token consists of nested APPLICATION tags:

```
APPLICATION 31 (constructed)
    └─ APPLICATION 30 (constructed)
         └─ SEQUENCE
              ├─ OBJECT IDENTIFIER : 1.3.6.1.4.1.19912.1.2
              ├─ UTF8String        : "PO-CGQ14.05.<unix_timestamp>"
              ├─ INTEGER           : 1
              ├─ INTEGER           : 0
              └─ BIT STRING        : <cryptographic signature>
```

* **OID** `1.3.6.1.4.1.19912.1.2` – identifies the token format.
* **UTF8String** contains a fixed prefix `PO-CGQ14.05.` followed by a Unix timestamp (seconds since epoch).  
  Example: `PO-CGQ14.05.2414080090` → UTC 2026‑06‑25 02:34:50.
* Two INTEGER fields (`1` and `0`) – likely version and a flag.
* **BIT STRING** holds the signature, computed over the inner APPLICATION 30 data using a device‑specific private key. The signature binds the token to a particular N‑code and device ID.

## How the Sample Maps

* Input hex (request) contains the same OID, the same UTF8String, and two zero‑DWORDs that likely encode timestamp and device ID.
* Output hex (token) adds the BIT STRING signature after the two INTEGERs, wrapped in APPLICATION 30 then APPLICATION 31.

## Usage

```python
from token_generator import DynamicToken

# Load device private key (PEM format)
with open('device_key.pem', 'rb') as f:
    key_data = f.read()

token = DynamicToken(device_key=key_data, n_code='LFVVA9EA5R5353299', device_id='019')

# Generate a token for current time
token_hex = token.build_token()
print(token_hex.hex())

# Parse a token
parsed = DynamicToken.parse_token(token_hex)
print(parsed)
```

## Implementation

See `token_generator/token.py` for the full parser/generator class.

## License

MIT
