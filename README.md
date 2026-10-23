# TrustVault - Secure Document Sharing

TrustVault is a Django web application designed to securely upload, share, and download documents with access permissions and an audit trail.

## Features

- User login and authentication
- Document upload with file validation
- Secure, permission-controlled document downloads
- Owner-controlled document sharing
- Read and edit permissions
- Revoke document access
- Audit logs for uploads, sharing, and downloads
- SHA-256 hash-linked audit events
- Audit-chain integrity verification
- Staff-only audit-log page
- Automated Django tests

## Technology Stack

- Python
- Django
- SQLite
- HTML and CSS

## Project Setup

### 1. Open the project folder

Open PowerShell in the folder containing `manage.py`.

### 2. Activate the virtual environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Django

```powershell
python -m pip install Django
```

### 4. Apply database migrations

```powershell
python manage.py migrate
```

### 5. Create an administrator account

```powershell
python manage.py createsuperuser
```

Follow the prompts to create the account.

### 6. Start the development server

```powershell
python manage.py runserver
```

Open the application in your browser:

http://127.0.0.1:8000/

## Application Pages

- Login: http://127.0.0.1:8000/accounts/login/
- Document upload: http://127.0.0.1:8000/documents/upload/
- Audit logs: http://127.0.0.1:8000/audit-logs/
- Django admin: http://127.0.0.1:8000/admin/

The audit-log page requires a staff account.

## Run Tests

```powershell
python manage.py check
python manage.py test documents
```

## Security

- Document owners and users with read or edit permissions can download documents.
- Only document owners can share documents or revoke access.
- Audit events are linked using SHA-256 hashes to help detect modifications.
- Audit-chain verification checks event hashes and links.
- Revoking access cannot remove copies already downloaded by users.
- The built-in Django development server is intended for development, not production.

## Project Purpose

This project was developed for the Snovasys Fresher Hiring Challenge 2026 to demonstrate document access control, permission management, and audit logging.
