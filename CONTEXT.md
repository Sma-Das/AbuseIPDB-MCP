# Domain context

## Abuse report draft

Untrusted report data received from an MCP caller. A draft is not ready for
submission until report intake has confirmed the write and validated every
field against the reporting policy.

## Abuse report

A normalized, policy-checked description of directly observed abuse. An abuse
report is safe to hand to an upstream adapter for either single or bulk
submission.

## Report intake

The domain module that turns abuse report drafts into abuse reports. It owns
write confirmation, IP and category normalization, comment limits, timestamp
rules, and bulk row limits. It does not own an upstream wire format.

## AbuseIPDB adapter

The module that translates abuse reports into AbuseIPDB API v2 requests. It
owns form and CSV encoding, authentication headers, response decoding, and
rate-limit metadata.
