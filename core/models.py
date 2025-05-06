from django.contrib.auth.models import AbstractUser
from django.db import models
import pyotp

USER_ROLES = [
    ('colaborador', 'Colaborador'),
    ('gestor', 'Gestor'),
]

class User(AbstractUser):
    role = models.CharField(max_length=20, choices=USER_ROLES, default='colaborador')
    totp_secret = models.CharField(max_length=32, blank=True, null=True)

    def get_totp_uri(self):
        return f'otpauth://totp/DocShare:{self.username}?secret={self.totp_secret}&issuer=DocShare'

    def generate_totp_secret(self):
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.save()

class Document(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    encrypted_file = models.FileField(upload_to='uploads_encrypted/')
    encrypted_key = models.BinaryField()
