
from django.urls import path
from . import views

urlpatterns = [
    path(
        "documents/upload/",
        views.upload_document,
        name="upload_document",
    ),
    path(
        "documents/<int:document_id>/download/",
        views.download_document,
        name="download_document",
    ),
    path(
        "documents/<int:document_id>/share/",
        views.share_document,
        name="share_document",
    ),
    
path("audit-logs/", views.audit_logs, name="audit_logs"),
path(
    "documents/<int:document_id>/revoke/<int:user_id>/",
    views.revoke_access,
    name="revoke_access",
),
]
