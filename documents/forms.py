from django import forms
from django.contrib.auth import get_user_model

from .models import Document
class DocumentUploadForm(forms.ModelForm):
    class Meta:
        model = Document
        fields = ["title", "description", "category", "file"]

    def clean_file(self):
        uploaded_file = self.cleaned_data.get("file")

        if not uploaded_file:
            raise forms.ValidationError("Please select a file.")

        max_size = 5 * 1024 * 1024  # 5 MB
        if uploaded_file.size > max_size:
            raise forms.ValidationError(
                "File size must not exceed 5 MB."
            )

        allowed_extensions = {".pdf", ".txt", ".docx", ".png", ".jpg", ".jpeg"}
        filename = uploaded_file.name.lower()
        extension = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

        if extension not in allowed_extensions:
            raise forms.ValidationError(
                "Allowed file types: PDF, TXT, DOCX, PNG, JPG, JPEG."
            )

        return uploaded_file

User = get_user_model()


class DocumentShareForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        label="Username",
    )

    permission = forms.ChoiceField(
        choices=[
            ("read", "Read only"),
            ("edit", "Can edit"),
        ],
        label="Permission",
    )

    def clean_username(self):
        username = self.cleaned_data["username"].strip()

        if not User.objects.filter(username=username).exists():
            raise forms.ValidationError(
                "No registered user found with this username."
            )

        return username
