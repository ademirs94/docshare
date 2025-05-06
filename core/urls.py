from django.shortcuts import render
from django.urls import path
from .views import (upload_document, signup, logout_view,
                    document_list, download_document,
                    login_view, verify_totp, setup_totp, delete_document)

from django.contrib.auth import views as auth_views

urlpatterns = [
    path('upload/', upload_document, name='upload'),
    # path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('login/', login_view, name='login'),
    path('verify-totp/', verify_totp, name='verify_totp'),
    path('setup-totp/', setup_totp, name='setup_totp'),
    path('upload-success/', lambda r: render(r, 'upload_success.html'), name='upload_success'),
    path('signup/', signup, name='signup'),
    path('logout/', logout_view, name='logout'),
    path('my-documents/', document_list, name='document_list'),
    path('', document_list, name='document_list'),
    path('download/<int:document_id>/', download_document, name='download_document'),
    path('document/delete/<int:document_id>/', delete_document, name='delete_document'),

]
