from django.shortcuts import render
from django.urls import path
from .views import (upload_document, signup, logout_view,
                    user_document_list, download_document,
                    login_view, verify_totp, setup_totp, delete_document,
                    create_group, get_groups, list_users, update_user_profile, get_user_profile, request_group_access, get_access_requests,
                    respond_access_request, update_member_role, manage_group_member, get_group_documents, get_document, add_document_view, toggle_document_like, create_comment, list_document_comments)

from django.contrib.auth import views as auth_views

urlpatterns = [
    path('upload/', upload_document, name='upload'),
    path('login/', login_view, name='login'),
    path('verify-totp/', verify_totp, name='verify_totp'),
    path('setup-totp/', setup_totp, name='setup_totp'),
    path('signup/', signup, name='signup'),
    path('my-documents/', user_document_list, name='user_document_list'),
    path('download/<int:document_id>/', download_document, name='download_document'),
    path('document/<int:document_id>/', get_document, name='get_document'),
    path('document/<int:document_id>/view/', add_document_view, name='add_document_view'),
    path('document/<int:document_id>/like/', toggle_document_like, name='toggle_document_like'),
    path('document/<int:document_id>/comment/', create_comment, name='create_comment'),
    path('document/<int:document_id>/comments/', list_document_comments, name='list_document_comments'),
    path('document/delete/<int:document_id>/', delete_document, name='delete_document'),
    path('groups/create/', create_group, name='create_group'),
    path('groups/<int:user_id>/', get_groups, name='get_groups'),
    path('users/', list_users, name='list_users'),
    path('user/profile/<int:user_id>/', get_user_profile, name='get_user_profile'),
    path('user/profile/', update_user_profile, name='update_user_profile'),
    path('groups/request/', request_group_access, name='request_group_access'),
    path('groups/requests/<int:user_id>/', get_access_requests, name='get_access_requests'),
    path('groups/requests/<int:request_id>/respond/', respond_access_request, name='respond_access_request'),
    path('groups/<int:group_id>/members/role/', update_member_role, name='update_member_role'),
    path('groups/<int:group_id>/member/', manage_group_member, name='manage_group_member'),
    path('groups/<int:group_id>/documents/', get_group_documents, name='get_group_documents'),

]
