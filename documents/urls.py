from django.urls import path
from . import views

urlpatterns = [
    path(
        "documents/<int:document_id>/download/",
        views.download_document,
        name="download_document",
    ),
]