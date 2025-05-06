from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User

class DocumentUploadForm(forms.Form):
    file = forms.FileField()


class SignUpForm(UserCreationForm):
    ROLE_CHOICES = [
        ('colaborador', 'Colaborador'),
        ('gestor', 'Gestor'),
    ]

    role = forms.ChoiceField(choices=ROLE_CHOICES)

    class Meta:
        model = User
        fields = ('username', 'email', 'role', 'password1', 'password2')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user
