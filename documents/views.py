import hashlib
import json
from django.views.decorators.http import (
    require_GET,
    require_http_methods,
    require_POST,
)

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.http import (
    FileResponse,
    Http404,
    HttpResponseForbidden,
)
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods

from .forms import DocumentShareForm, DocumentUploadForm
from .models import AuditLog, Document, DocumentPermission
def home(request):
    return render(request, "documents/home.html")


def record_audit(actor, document, action, outcome):
    """Record an audit event and link it to the previous event."""
    previous_event = AuditLog.objects.order_by("-id").first()
    previous_hash = previous_event.event_hash if previous_event else ""

    log = AuditLog.objects.create(
        actor=actor,
        document=document,
        action=action,
        outcome=outcome,
        previous_hash=previous_hash,
    )

    event_data = {
        "id": log.id,
        "actor_id": log.actor_id,
        "document_id": log.document_id,
        "action": log.action,
        "outcome": log.outcome,
        "details": log.details,
        "timestamp": log.timestamp.isoformat(),
        "previous_hash": log.previous_hash,
    }

    event_json = json.dumps(
        event_data,
        sort_keys=True,
        separators=(",", ":"),
    )

    log.event_hash = hashlib.sha256(
        event_json.encode("utf-8")
    ).hexdigest()

    log.save(update_fields=["event_hash"])


def verify_audit_chain():
    """Verify event hashes and links throughout the audit chain."""
    previous_hash = ""

    for log in AuditLog.objects.order_by("id"):
        if log.previous_hash != previous_hash:
            return False

        event_data = {
            "id": log.id,
            "actor_id": log.actor_id,
            "document_id": log.document_id,
            "action": log.action,
            "outcome": log.outcome,
            "details": log.details,
            "timestamp": log.timestamp.isoformat(),
            "previous_hash": log.previous_hash,
        }

        event_json = json.dumps(
            event_data,
            sort_keys=True,
            separators=(",", ":"),
        )

        expected_hash = hashlib.sha256(
            event_json.encode("utf-8")
        ).hexdigest()

        if log.event_hash != expected_hash:
            return False

        previous_hash = log.event_hash

    return True


def can_read_document(user, document):
    """Allow access only to the owner or a user with read/edit permission."""
    if document.owner_id == user.id:
        return True

    return DocumentPermission.objects.filter(
        document=document,
        user=user,
        permission__in=[
            DocumentPermission.READ,
            DocumentPermission.EDIT,
        ],
    ).exists()


@login_required
@require_http_methods(["GET", "POST"])
def upload_document(request):
    """Upload a document and list the current user's documents."""
    if request.method == "POST":
        form = DocumentUploadForm(request.POST, request.FILES)

        if form.is_valid():
            document = form.save(commit=False)
            document.owner = request.user
            document.save()

            record_audit(
                request.user,
                document,
                "upload",
                "success",
            )

            return redirect("upload_document")
    else:
        form = DocumentUploadForm()

    documents = Document.objects.filter(
        owner=request.user
    ).order_by("-created_at")

    return render(
        request,
        "documents/upload.html",
        {
            "form": form,
            "documents": documents,
        },
    )


@login_required
@require_GET
def download_document(request, document_id):
    """Download a document only when the user has permission."""
    document = get_object_or_404(Document, pk=document_id)

    if not can_read_document(request.user, document):
        record_audit(
            request.user,
            document,
            "download",
            "denied",
        )

        return HttpResponseForbidden(
            "You do not have permission to access this document."
        )

    try:
        file_handle = document.file.open("rb")
    except (OSError, ValueError):
        record_audit(
            request.user,
            document,
            "download",
            "failed",
        )

        raise Http404("Document file is unavailable.")

    record_audit(
        request.user,
        document,
        "download",
        "success",
    )

    return FileResponse(
        file_handle,
        as_attachment=True,
        filename=document.file.name.split("/")[-1],
    )


@login_required
@require_http_methods(["GET", "POST"])
def share_document(request, document_id):
    """Allow only the document owner to grant or update permissions."""
    document = get_object_or_404(Document, pk=document_id)

    if document.owner_id != request.user.id:
        record_audit(
            request.user,
            document,
            "share",
            "denied",
        )

        return HttpResponseForbidden(
            "Only the document owner can share this document."
        )

    if request.method == "POST":
        form = DocumentShareForm(request.POST)

        if form.is_valid():
            User = DocumentPermission._meta.get_field(
                "user"
            ).remote_field.model

            recipient = get_object_or_404(
                User,
                username=form.cleaned_data["username"],
            )

            if recipient.id == document.owner_id:
                form.add_error(
                    "username",
                    "You already own this document.",
                )
            else:
                permission_value = form.cleaned_data["permission"]

                DocumentPermission.objects.update_or_create(
                    document=document,
                    user=recipient,
                    defaults={
                        "permission": permission_value,
                        "granted_by": request.user,
                    },
                )

                record_audit(
                    request.user,
                    document,
                    "share",
                    "success",
                )

                return redirect("upload_document")
    else:
        form = DocumentShareForm()


    permissions = document.permissions.select_related(
        "user"
    ).all()

    return render(
        request,
        "documents/share.html",
        {
            "document": document,
            "form": form,
            "permissions": permissions,
        },
    )



@staff_member_required
@require_GET
def audit_logs(request):
    """Display the latest audit events to staff users only."""
    logs = AuditLog.objects.select_related(
        "actor",
        "document",
    ).order_by("-timestamp", "-id")[:100]

    return render(
        request,
        "documents/audit_logs.html",
        {"logs": logs},
    )

@login_required
@require_POST
def revoke_access(request, document_id, user_id):
    document = get_object_or_404(
        Document,
        pk=document_id,
    )

    # Only the owner can revoke access.
    if document.owner_id != request.user.id:
        record_audit(
            request.user,
            document,
            "revoke_access",
            "denied",
        )
        return HttpResponseForbidden(
            "Only the document owner can revoke access."
        )

    permission = DocumentPermission.objects.filter(
        document=document,
        user_id=user_id,
    ).first()

    if permission:
        permission.delete()
        record_audit(
            request.user,
            document,
            "revoke_access",
            "success",
        )
    else:
        record_audit(
            request.user,
            document,
            "revoke_access",
            "not_found",
        )

    return redirect("upload_document")
