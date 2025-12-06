from django.contrib.auth.models import AbstractUser
from django.db import models
import pyotp

GROUP_MEMBER_ROLES = [
    ('membro', 'Membro'),
    ('admin', 'Administrador'),
    ('moderador', 'Moderador'),
]

class User(AbstractUser):
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
    shared_in_group = models.ForeignKey('Group', on_delete=models.CASCADE, blank=True, null=True)
    shared_with_user = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True, related_name='shared_documents')

class Group(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=100, blank=True, null=True)
    image = models.CharField(max_length=255, blank=True, null=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_groups')
    created_date = models.DateTimeField(auto_now_add=True)
    members = models.ManyToManyField(User, related_name='groups_member', through='GroupMember')

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['-created_date']

class GroupMember(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='group_members')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_memberships')
    role = models.CharField(max_length=20, choices=GROUP_MEMBER_ROLES, default='membro')
    joined_date = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('group', 'user')
        ordering = ['-joined_date']

    def __str__(self):
        return f'{self.user.username} - {self.group.name} ({self.role})'


REQUEST_STATUS = [
    ('pending', 'Pendente'),
    ('approved', 'Aprovado'),
    ('rejected', 'Rejeitado'),
]


class RequestAccess(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='access_requests')
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='access_requests')
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='pending')
    requested_date = models.DateTimeField(auto_now_add=True)
    responded_date = models.DateTimeField(blank=True, null=True)
    message = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('user', 'group')
        ordering = ['-requested_date']

    def __str__(self):
        return f'{self.user.username} - {self.group.name} ({self.status})'
