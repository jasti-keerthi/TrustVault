
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from .models import AuditLog, Document, DocumentPermission

User = get_user_model()


class DocumentSecurityTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            username="owner",
            password="TestPass123!",
        )
        self.other_user = User.objects.create_user(
            username="other",
            password="TestPass123!",
        )

        self.document = Document.objects.create(
            owner=self.owner,
            title="Private document",
            description="Test file",
            category="Test",
            file=SimpleUploadedFile(
                "private.txt",
                b"secret content",
                content_type="text/plain",
            ),
        )

        self.url = reverse(
            "download_document",
            args=[self.document.pk],
        )

    def test_anonymous_user_is_redirected_to_login(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)

    def test_owner_can_download_document(self):
        self.client.login(
            username="owner",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response["Content-Disposition"].startswith("attachment"))

    def test_unshared_user_cannot_download_document(self):
        self.client.login(
            username="other",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        self.assertTrue(
            AuditLog.objects.filter(
                actor=self.other_user,
                document=self.document,
                action="download",
                outcome="denied",
            ).exists()
        )

    def test_user_with_read_permission_can_download(self):
        DocumentPermission.objects.create(
            document=self.document,
            user=self.other_user,
            permission=DocumentPermission.READ,
            granted_by=self.owner,
        )

        self.client.login(
            username="other",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)

    def test_revoked_permission_blocks_download(self):
        permission = DocumentPermission.objects.create(
            document=self.document,
            user=self.other_user,
            permission=DocumentPermission.READ,
            granted_by=self.owner,
        )
        permission.delete()

        self.client.login(
            username="other",
            password="TestPass123!",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
    
    def test_audit_logs_link_to_previous_hash(self):
        first = AuditLog.objects.create(
            actor=self.owner,
            document=self.document,
            action="upload",
            outcome="success",
        )
        first.event_hash = "a" * 64
        first.save(update_fields=["event_hash"])

        from .views import record_audit

        record_audit(
            self.owner,
            self.document,
            "download",
            "success",
        )

        latest = AuditLog.objects.latest("id")

        self.assertEqual(latest.previous_hash, first.event_hash)
        self.assertTrue(latest.event_hash)
        self.assertEqual(len(latest.event_hash), 64)
    
    def test_audit_logs_link_to_previous_hash(self):
        from .views import record_audit

        record_audit(
            self.owner,
            self.document,
            "upload",
            "success",
        )

        first = AuditLog.objects.latest("id")

        record_audit(
            self.owner,
            self.document,
            "download",
            "success",
        )

        latest = AuditLog.objects.latest("id")

        self.assertTrue(first.event_hash)
        self.assertEqual(len(first.event_hash), 64)
        self.assertEqual(latest.previous_hash, first.event_hash)
        self.assertTrue(latest.event_hash)
        self.assertEqual(len(latest.event_hash), 64)
    
    def test_audit_chain_detects_tampering(self):
        from .views import record_audit, verify_audit_chain

        record_audit(self.owner, self.document, "upload", "success")

        self.assertTrue(verify_audit_chain())

        log = AuditLog.objects.latest("id")
        log.action = "tampered"
        log.save(update_fields=["action"])

        self.assertFalse(verify_audit_chain())

