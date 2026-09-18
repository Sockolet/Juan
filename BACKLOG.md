# Juan backlog

## SAZ-001 - Fiddler SAZ import and export

**Status:** Initial scope implemented in v0.2.0.  
**Requested:** September 17, 2026.  
**Purpose:** Let support engineers open customer Fiddler captures and exchange
Juan captures with the Fiddler ecosystem, while retaining HAR support.

### Delivered initial scope

- Open unencrypted SAZ archives using a native Rust ZIP/HTTP/XML reader, without
  starting the proxy or changing routing or certificate trust.
- Export request (`_c.txt`), response (`_s.txt`), and available session metadata
  (`_m.xml`) in the expected archive structure.
- Include a compatible, safely escaped `_index.htm` with session links:
  Eric Lawrence's SAZView requires this index.
- Preserve available headers, binary/compressed body bytes, timing, and metadata.
  Explicitly identify incomplete/truncated captures and unavailable information.
- Enforce archive entry/size/decompression limits, reject unsafe paths, and do
  not execute archive HTML/scripts or resolve external XML entities.
- Verify interoperability with Fiddler Classic and SAZView, including actual body
  bytes. SAZView's header inspector alone is not a full-fidelity check.

Password-protected archives, comprehensive Fiddler-specific metadata round-trips,
and WebSocket message payloads are separately scoped follow-ups. SAZ export cannot
recover payloads the capture engine never retained.

Validation includes a synthetic archive generated through installed Fiddler
Classic's public offline APIs, Fiddler read-back with matching URL/body hashes,
the unmodified SAZView loader and session-link handlers, bounded-parser regression
tests, and native desktop archive workflows. Imported HTML is never executed.

Reference: [ericlaw1979/sazview](https://github.com/ericlaw1979/sazview).
