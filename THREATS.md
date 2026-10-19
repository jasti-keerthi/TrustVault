# TrustVault — Threat Model

## 1. Project Overview

TrustVault is a Django document-sharing application designed to protect private documents through user authentication, ownership, and access permissions.

## 2. Assets to Protect

- Private documents and their contents.
- User accounts and authentication sessions.
- Document ownership and access permissions.
- Audit logs and document activity records.
- Permission changes and deletion records.

## 3. Threats and Mitigations

### Threat 1: Unauthorized Document Access

**Risk:** A user changes a document ID in a URL to access another user's document.

**Mitigation:** Check authentication, ownership, and document permissions on every protected request. Test access with different user accounts.

### Threat 2: Unauthorized Downloads

**Risk:** A user without permission attempts to download a private file.

**Mitigation:** Check authorization before opening or returning the file. Deny unauthorized requests and record the attempt in the audit log.

### Threat 3: Permission Abuse

**Risk:** An unauthorized user attempts to grant, change, or revoke document permissions.

**Mitigation:** Only allow authorized owners or administrators to manage permissions, according to the application's policy. Test allowed and denied permission changes.

### Threat 4: Malicious File Uploads

**Risk:** A user uploads an unsafe, disallowed, or excessively large file.

**Mitigation:** Validate file types and file sizes. Store documents outside publicly accessible directories. File extensions alone cannot prove a file is safe.

### Threat 5: Audit Log Tampering

**Risk:** Someone attempts to alter or delete records of document activity.

**Mitigation:** Restrict audit-log access. Consider hash-linked records and integrity verification. Hash chaining alone does not prevent tampering if an attacker can rewrite the entire chain.

### Threat 6: Sensitive Information Leakage

**Risk:** Public file paths, error messages, or logs expose private information.

**Mitigation:** Keep private documents out of publicly served directories. Avoid logging passwords or document contents. Use appropriate error responses.

### Threat 7: Unauthorized Editing or Deletion

**Risk:** A user changes or deletes a document without permission.

**Mitigation:** Enforce server-side authorization for every edit and delete operation. Test that unauthorized users cannot change or delete documents.

### Threat 8: Authentication and Session Abuse

**Risk:** An unauthenticated user or attacker with a stolen session attempts to access protected features.

**Mitigation:** Require authentication, use Django's security protections, and configure secure cookies and HTTPS for production.

## 4. Security Testing Checklist

- [x] Owner download test passes.
- [x] Anonymous access test passes.
- [x] Unauthorized download test passes.
- [x] Read-permission download test passes.
- [x] Revoked-permission test passes.
- [ ] Test edit and delete permissions.
- [ ] Test permission-grant and permission-revocation authorization.
- [ ] Test file-upload validation.
- [ ] Test audit logging for all required actions.
- [ ] Test audit-log integrity.

## 5. Current Security Status

On October 19, 2026, five automated document-access tests passed.

Only the scenarios covered by those tests have been verified. The remaining checklist items require implementation and testing before they can be considered complete.

## 6. Residual Risks

Application-level controls cannot guarantee that every uploaded file is harmless or that a compromised server will preserve private documents and audit records. Production deployment also requires secure storage permissions, appropriate configuration, backups, and regular security testing.
