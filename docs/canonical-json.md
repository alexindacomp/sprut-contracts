# Canonical JSON and hash (CF03)

Status: normative for `schema_version` 1. Applies to every Sprut structure that
carries a `hash` member (manifests, plans, journals and similar records). The
Java client, the Go client and the coordinator must produce byte-identical
canonical text and identical hashes for the same value;
`test-vectors/canonical-json*/` proves it.

## 1. Serialization: RFC 8785 (JCS), restricted

The canonical form is the JSON Canonicalization Scheme,
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), applied to a value that
satisfies the restrictions in section 3. Under those restrictions JCS reduces to
these rules:

1. **No insignificant whitespace.** No spaces, tabs or newlines between tokens.
2. **Objects.** Members are sorted by name, comparing names as sequences of
   **UTF-16 code units** (unsigned 16-bit values), lexicographically; a name
   that is a prefix of another sorts first. Sorting applies recursively to every
   nested object, including objects inside arrays.
   - Java: `String.compareTo` already compares UTF-16 code units.
   - Go: `sort.Strings` compares UTF-8 bytes (code points) and is **wrong** for
     characters above U+FFFF versus U+E000..U+FFFF. Compare
     `utf16.Encode([]rune(s))` instead. Vector `key-ordering-utf16-code-units`
     catches the difference.
3. **Arrays.** Element order is preserved.
4. **Strings.** Written between `"` with only these escapes:
   - `"` as `\"`, `\` as `\\`;
   - U+0008 `\b`, U+0009 `\t`, U+000A `\n`, U+000C `\f`, U+000D `\r`;
   - every other character U+0000..U+001F as `\u00XX` with **lowercase** hex.

   Everything else, including `/`, U+007F, U+2028/U+2029 and all non-ASCII
   characters (Cyrillic, CJK, emoji), is written as is. No Unicode
   normalization is applied: `é` (U+00E9) and `e` + U+0301 are different.
   - Go: `encoding/json` escapes `<`, `>`, `&` unless HTML escaping is turned
     off, and always escapes U+2028/U+2029, so it cannot produce JCS strings;
     use a dedicated string writer (vector `string-escaping`).
   - Java: generic serializers differ in escaping options; use a dedicated
     writer and check it against the vectors.
5. **Integers.** Decimal, `-` only for negative values, no leading zeros, no `+`,
   no fraction, no exponent: `0`, `-1`, `9007199254740991`.
6. **Literals.** `true`, `false`, `null`.
7. **Encoding.** The canonical text is encoded as UTF-8 without a BOM. This byte
   sequence is what is hashed.

## 2. Hash

```
object_hash(obj) = lowercase_hex( SHA-256( UTF-8( JCS( obj without its top-level "hash" member ) ) ) )
```

- **Domain separation.** Every hashed structure carries a top-level `kind`
  member, a lower_snake_case string naming the structure type (for example
  `installation_plan`, `model_manifest`, `bootstrap_journal`). `kind` is part of
  the hashed content, so two structures with the same members but a different
  `kind` never share a hash (vectors `object-hash-domain-*`). `object_hash`
  rejects an object without a valid `kind` (`INVALID_KIND`). A verifier always
  knows which kind it expects at a position (an InstallationPlan where a plan is
  consented, a ModelManifest where a model is loaded). It rejects a well-formed
  object of any other kind with `INVALID_KIND` before comparing hashes, so a
  structure of one type can never be substituted for another (vectors carry
  this as `expected_kind`; see `reject-unexpected-kind`).
- Only the member named exactly `hash` at the **top level of the object being
  hashed** is removed before canonicalization. Nested members named `hash`
  (for example hashes of files or sub-objects), members such as
  `hash_algorithm`, and members that differ only in case (`Hash`) are kept and
  hashed.
- If the object has no `hash` member, nothing is removed. If it has one, the
  value must be a string matching `^[0-9a-f]{64}$`; anything else (a number, upper
  case, a `sha256:` prefix) is rejected with `INVALID_HASH_MEMBER` before any
  comparison.
- The result is 64 lowercase hexadecimal characters, with no prefix.
- `object_hash` is defined for JSON objects only.
- **Hash what you received.** The hash covers every member of the received
  object, including members this implementation does not know. Dropping unknown
  members is an OperationEvent-consumer rule only; it never applies before
  hashing or verifying.
- **Recompute, never trust storage.** To verify a stored object, compute
  `object_hash` from the exact parsed value that will be displayed or executed
  and compare it with the expected identifier as a string. An identifying hash is
  always recomputed this way; a `hash` read from a journal, cache or file is never
  used as the identifier by itself.
- **Identifying hashes.** When the specification identifies a structure by its
  hash (for example "`plan_id` is the hash of the InstallationPlan", CF12), the
  identifier is the value of that structure's own top-level `hash` member. It is
  not stored as a second member of the same structure: any other member would be
  part of the hashed content and could never equal the result. Other records
  refer to the structure by that value (for example
  `sprut setup apply --plan-id <hash> --yes`). The concrete InstallationPlan
  format is defined together with InstallationPlan.

Vectors with `"operation": "object_hash"` test this rule; vectors with
`"operation": "canonicalize"` test plain JCS of `input`. In every vector,
`sha256` is the SHA-256 of the UTF-8 bytes of `canonical`.

## 3. Restrictions on hashed values (cross-language parity)

A structure that is hashed must satisfy all of the following. An implementation
must **refuse** to canonicalize input that violates them and report the error
category from section 5; it must not repair the input.

1. **Integers only, within ±(2^53 − 1)** (−9007199254740991 … 9007199254740991).
   Larger values do not survive an IEEE-754 double (JavaScript, many JSON
   libraries) and must be sent as decimal strings. Check the digit count (at most
   16 digits) before converting a token to a number, so that a token with
   thousands of digits gives `INTEGER_OUT_OF_RANGE` rather than a parser error or
   a slow conversion (vector `reject-huge-integer`).
2. **No non-integer numbers** in hashed structures: no fraction and no exponent,
   even when the value is integral (`1.0`, `1e3`, `1E3`). Floating-point
   shortest round-trip formatting differs between libraries. This is a hard rule
   for `schema_version` 1: any future decimal field of a hashed structure (for
   example a learning rate in a RunManifest) is defined either as a decimal
   string (`"0.001"`) or as a scaled integer (milliseconds, bytes, parts per
   million), never as a JSON number with a fraction. `-0.0` and `-0e0` are
   `NON_INTEGER_NUMBER` (they have a fraction or exponent); only the integer
   token `-0` is `NEGATIVE_ZERO`.
3. **No `-0`, `NaN`, `Infinity`.** In JSON text, `NaN` and `Infinity` are not
   tokens at all, so such text is `INVALID_JSON`, as is a leading zero (`01`).
   `NON_FINITE_NUMBER` applies when an implementation is asked to serialize an
   in-memory non-finite float.
4. **No duplicate member names** at any depth, compared after unescaping
   (`"\u0061"` and `"a"` are the same name). The input is rejected, not
   resolved "last wins".
5. **Valid Unicode only.** The input bytes must be well-formed UTF-8, and strings
   must not contain lone surrogates (for example the escape `\ud800` without
   its pair). Malformed input is rejected, never replaced with U+FFFD.
6. **Limits.** A received document is at most **1 MiB** (1048576 bytes, the
   control payload limit of spec 9) and nests arrays/objects at most **64** deep
   (the top-level container is depth 1). Check the size before decoding and the
   depth before or while parsing (`SIZE_LIMIT`, `DEPTH_LIMIT`), so that hostile
   input cannot exhaust memory or the stack.
7. The top-level value of `object_hash` must be an object with a valid `kind`
   (section 2).

### 3.1. Parser traps

Common library defaults silently repair exactly the input that must be rejected:

| Trap | Go (`encoding/json`) | Java |
|---|---|---|
| Fraction turned into an integer (`1.0` → `1`) | Decoding into `interface{}` gives `float64`; use `json.Decoder.UseNumber()` and inspect the `json.Number` text | Jackson: inspect the token type (`VALUE_NUMBER_FLOAT`) before reading a value |
| Duplicate keys | Accepted silently, last value wins; detect duplicates with a token-level pass (`Decoder.Token`) | Jackson: enable `JsonParser.Feature.STRICT_DUPLICATE_DETECTION` |
| Invalid UTF-8 | Replaced with U+FFFD on decode; check `utf8.Valid(raw)` first | `new String(bytes, UTF_8)` replaces malformed input with U+FFFD; decode with a `CharsetDecoder` set to `CodingErrorAction.REPORT` |
| Lone surrogate escapes (`"\ud800"`) | Replaced with U+FFFD on decode; check escapes at the token level | Accepted into `String`; check for unpaired surrogates (`Character.isSurrogate`) |
| Deep nesting / huge input | No depth limit in `encoding/json`; check size and depth first | Jackson: set `StreamReadConstraints` (max nesting depth, max document length, max number length) |
| Number-length caps | A token-length cap of your own (or of a streaming decoder) on number tokens | Jackson `StreamReadConstraints.maxNumberLength` throws `StreamConstraintsException` |

A violated **number-length** constraint (Jackson `maxNumberLength`, a Go token
cap or any other library limit on the digits of a number) is reported as
`INTEGER_OUT_OF_RANGE`, not as `INVALID_JSON`. Similarly, nesting and document
size limits map to `DEPTH_LIMIT` and `SIZE_LIMIT`. Map the library exception to
the category; do not report the library's own error.

The vectors `reject-duplicate-key-escaped`, `reject-invalid-utf8-byte`,
`reject-utf8-encoded-surrogate`, `reject-lone-surrogate`, `reject-depth-65-*`,
`reject-size-over-1mib` and `reject-huge-integer` catch these.

When an input contains several violations, the implementation should report the
first one in document order. Conformance vectors contain exactly one violation
each, so tests do not depend on this ordering.

### 3.2. Regular expressions in the JSON Schemas

Every `pattern` in `schemas/` is anchored `^...$` and must match the **whole**
string. ECMA-262 and Go RE2 treat `$` (without the multiline flag) as the very
end of the text. Java `Matcher.find()` and Python `re.search` let `$` match
before a trailing newline, so `"PROBING\n"` would pass: in Java use
`Pattern.matches()` / `Matcher.matches()` (or `\z`), in Python `re.fullmatch`
(or `\Z`). The OperationEvent vectors `*-trailing-newline` catch this.

## 4. Test vectors

| Directory | Content |
|---|---|
| `test-vectors/canonical-json/` | `{name, description, operation, input, canonical, sha256}`; implementations must reproduce `canonical` from `input` byte for byte and `sha256` from `canonical`. The vector files themselves satisfy section 3 (the 64-deep vector is a file nested 65 deep, so apply the 64 limit to `input`, not to the vector file) |
| `test-vectors/canonical-json-invalid/` | `{name, description, operation, input_text \| input_base64 \| input_generated, expected_error}`; `input_text` is raw JSON text (kept as a string so the vector file's own parser cannot normalise it; encode it as UTF-8 to get the bytes), `input_base64` is raw bytes that are not valid UTF-8, `input_generated` is `prefix + repeat × count + suffix` for inputs too large to store; `operation` is `canonicalize` or `object_hash`; implementations must reject the input with the given category |

`tools/validate.py` is the reference implementation used to check the vectors.

## 5. Error categories for rejected input

| Category | Meaning |
|---|---|
| `INVALID_JSON` | Not well-formed JSON (RFC 8259), including the non-tokens `NaN`, `Infinity`, `-Infinity` and leading zeros |
| `DUPLICATE_KEY` | An object has two members with the same name (after unescaping) |
| `NON_INTEGER_NUMBER` | A number has a fraction or an exponent |
| `INTEGER_OUT_OF_RANGE` | An integer is outside ±(2^53 − 1), including tokens with more than 16 digits |
| `NEGATIVE_ZERO` | The integer token `-0` |
| `NON_FINITE_NUMBER` | Serializing an in-memory NaN or infinity |
| `INVALID_UNICODE` | Malformed UTF-8 bytes, or a string with a lone surrogate |
| `DEPTH_LIMIT` | Arrays/objects nested deeper than 64 |
| `SIZE_LIMIT` | Received document larger than 1 MiB |
| `INVALID_KIND` | `object_hash` of an object without a lower_snake_case top-level `kind` |
| `INVALID_HASH_MEMBER` | `object_hash` of an object whose top-level `hash` is not a string of 64 lowercase hex digits |

These categories identify conformance failures in tests and logs. They are not
user-facing reason codes; a client that receives a malformed hashed structure
reports the reason code of the surrounding operation (for example
`INTEGRITY_MISMATCH`).
