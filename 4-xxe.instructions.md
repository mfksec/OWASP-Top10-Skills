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

## Examples

**Vulnerable Python (lxml):**
```python
from lxml import etree

def load(xml_string):
    # default parser resolves external entities
    parser = etree.XMLParser()
    return etree.fromstring(xml_string, parser)
```

**Safe Python:**
```python
from lxml import etree

def load(xml_string):
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False)
    return etree.fromstring(xml_string, parser)
```

**Java (insecure):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
```

**Java (hardened):**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
```

## Prevention Checklist

- [ ] DTD processing and external entity resolution are disabled by
      default.
- [ ] Parser configurations are explicit and set to safe values.
- [ ] Incoming XML is validated against a strict schema before parsing.
- [ ] Any XML input sources (file uploads, SOAP messages, SAML
      assertions) are treated as untrusted.
- [ ] Dependencies are reviewed to ensure no library re-enables XXE in
      alternative APIs.
- [ ] Consider switching to simpler formats such as JSON when XML
      features aren’t required.

