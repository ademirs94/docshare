from django.shortcuts import render
from django.urls import path
from .views import (upload_document, signup, logout_view,
                    user_document_list, download_document,
                    login_view, verify_totp, setup_totp, delete_document,
                    create_group, get_groups, list_users, request_group_access, get_access_requests,
                    respond_access_request, update_member_role, manage_group_member, get_group_documents, get_document)

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
    path('my-documents/', user_document_list, name='user_document_list'),
    path('download/<int:document_id>/', download_document, name='download_document'),
    path('document/<int:document_id>/', get_document, name='get_document'),
    path('document/delete/<int:document_id>/', delete_document, name='delete_document'),
    path('groups/create/', create_group, name='create_group'),
    path('groups/<int:user_id>/', get_groups, name='get_groups'),
    path('users/', list_users, name='list_users'),
    path('groups/request/', request_group_access, name='request_group_access'),
    path('groups/requests/<int:user_id>/', get_access_requests, name='get_access_requests'),
    path('groups/requests/<int:request_id>/respond/', respond_access_request, name='respond_access_request'),
    path('groups/<int:group_id>/members/role/', update_member_role, name='update_member_role'),
    path('groups/<int:group_id>/member/', manage_group_member, name='manage_group_member'),
    path('groups/<int:group_id>/documents/', get_group_documents, name='get_group_documents'),

]
