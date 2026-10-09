# container/ — ASiC zip reading

Notes (verified in AsicHelper/AsicContainer 7.8.3):
- Read loop: name equalsIgnoreCase an expected entry (signature: case-sensitive regex META-INF/.*signatures.*\.xml) → store under
  actual name; else startsWith("attachment") (case-sensitive) → SHA-512 digest. Port stores only exact canonical names.
- Java ZipInputStream reads local headers; a non-zip input yields zero entries → asic_mime_type_not_found.
- Blank = commons-lang3 isBlank (Character.isWhitespace).
- Signature parse at read time (embedded timestamp) = new Signature(xml): DOM parse (DOCTYPE → SAXParseException → **invalid_xml**,
  not malformed_signature), first `ds:Signature` (else malformed_signature 'Could not find element "ds:Signature"'),
  Santuario XMLSignature (src/xades hook), first `ds:Object` (else malformed_signature), then EncapsulatedTimeStamp lookup.
