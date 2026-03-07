# 4. XML External Entities (XXE)

XXE occurs when XML parsers process external entity references within user-
controlled XML documents. This can lead to sensitive file disclosure,
port scanning, server-side request forgery, or denial of service.

## Indicators

- Use of `xml.etree`, `javax.xml`, `lxml`, `libxml2`, or similar
  libraries parsing XML from untrusted sources.
- Configuration flags like `ENTITY`, `resolve_entities`, or `allow_dtd`
  being enabled.
- Code reading files based on `SYSTEM` or `PUBLIC` entity definitions.

## Preventive steps

1. **Disable DTD processing** or external entity resolution by default.
   Most libraries offer a safe mode (e.g., `XMLParser(resolve_entities=False)`
   in Python).
2. **Use a simple data format** like JSON when XML capabilities aren’t
   needed.
3. **Validate and sanitize XML** against a strict schema before parsing.
4. **Run parsers in sandboxed environments** or with limited network
   access to mitigate SSRF consequences.

## Common pitfalls and bypasses

- XML bombs (`<!ENTITY a "&a;&a;">`) causing exponential expansion.
- Using insecure third-party libraries that re-enable XXE in later
  methods (e.g., `libxml2`’s `parseMemory` vs `parseFile`).
- Ignoring non-XML input types such as SOAP or RSS feeds.

## Quick checklist

- [ ] Is DTD and entity parsing disabled for all XML input?
- [ ] Are parser configurations explicitly set to safe defaults?
- [ ] Could an attacker upload or send arbitrary XML (e.g., in file
      uploads, SOAP, SAML assertions)?
- [ ] Are you using a library known to be secure or patched against XXE?

> The model should caution that even systems that only generate XML
> could be at risk if they later parse untrusted XML (e.g., in a
> microservice architecture).
