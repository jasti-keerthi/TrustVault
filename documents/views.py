import hashlib
import json
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404, HttpResponseForbidden
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

from .models import AuditLog, Document, DocumentPermission



def record_audit(actor, document, action, outcome):
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

    event_json = json.dumps(event_data, sort_keys=True, separators=(",", ":"))
    log.event_hash = hashlib.sha256(event_json.encode("utf-8")).hexdigest()
    log.save(update_fields=["event_hash"])


def verify_audit_chain():
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

    # Build a consistent representation of the saved event.
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


def can_read_document(user, document):
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
@require_GET
def download_document(request, document_id):
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
