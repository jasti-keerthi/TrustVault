
from django.conf import settings
from django.db import models


class Document(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_documents",
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=100, blank=True)
    file = models.FileField(upload_to="private_documents/")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class DocumentPermission(models.Model):
    READ = "read"
    EDIT = "edit"

    PERMISSION_CHOICES = [
        (READ, "Read"),
        (EDIT, "Edit"),
    ]

    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        related_name="permissions",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="document_permissions",
    )
    permission = models.CharField(
        max_length=10,
        choices=PERMISSION_CHOICES,
    )
    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="permissions_granted",
    )
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["document", "user"],
                name="unique_document_user_permission",
            )
        ]

    def __str__(self):
        return f"{self.user} - {self.document} ({self.permission})"

    
class AuditLog(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    document = models.ForeignKey(
        Document,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    action = models.CharField(max_length=50)
    outcome = models.CharField(max_length=20, default="success")
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    event_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ["-timestamp", "-id"]

    def __str__(self):
        return f"{self.action} - {self.outcome} - {self.timestamp}"

