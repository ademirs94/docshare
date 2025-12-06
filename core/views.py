from django.shortcuts import redirect
from docshare import settings
from .forms import DocumentUploadForm
from .models import Document, User, Group, GroupMember, RequestAccess
from .forms import SignUpForm
from django.contrib.auth import login, authenticate, logout
from django.http import HttpResponse
from .utils import decrypt_file, decrypt_key, encrypt_key, encrypt_file
from django.db.models import Q
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
import os
import uuid
from datetime import datetime

from django.core.files.storage import default_storage

from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view


def order_members_with_owner_first(members_list, group):
    """Ordena a lista de membros com o owner sempre em primeiro"""
    members = list(members_list)
    owner_member = None
    
    # Encontrar o owner
    for member in members:
        if member.user == group.created_by:
            owner_member = member
            break
    
    # Se encontrou o owner, coloca-o em primeiro
    if owner_member:
        members.remove(owner_member)
        members.insert(0, owner_member)
    
    return members


def get_file_extension(filename):
    """Extrai a extensão do ficheiro"""
    if '.' in filename:
        return filename.split('.')[-1].lower()
    return 'unknown'

@api_view(['POST'])
def upload_document(request):
    # Obtém o user_id, group_id e shared_with_user_id do formulário
    user_id = request.POST.get('user_id')
    group_id = request.POST.get('group_id')
    shared_with_user_id = request.POST.get('shared_with_user_id')

    # Valida que group_id e shared_with_user_id não são fornecidos juntos
    if group_id and shared_with_user_id:
        return Response({'detail': 'Cannot specify both group_id and shared_with_user_id'}, status=status.HTTP_400_BAD_REQUEST)

    # user_id é sempre obrigatório (é o owner do documento)
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    user = None
    group = None
    shared_with_user = None

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if group_id:
        try:
            group = Group.objects.get(id=group_id)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    if shared_with_user_id:
        try:
            shared_with_user = User.objects.get(id=shared_with_user_id)
        except User.DoesNotExist:
            return Response({'detail': 'Shared user not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verifica se há arquivo no request
    if 'file' not in request.FILES:
        return Response({'detail': 'Missing file'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Lê os dados do arquivo
        file_obj = request.FILES['file']
        file_data = file_obj.read()
        file_size = len(file_data)  # Guarda o tamanho do arquivo em bytes

        # Encripta o arquivo
        key, encrypted = encrypt_file(file_data)

        # Encripta a chave com a chave mestra
        encrypted_key = encrypt_key(key, settings.MASTER_KEY)

        # Cria o documento no banco de dados
        doc = Document.objects.create(
            owner=user,
            filename=file_obj.name,
            encrypted_file=None,
            encrypted_key=encrypted_key,
            file_size=file_size,  # Guarda o tamanho do arquivo
            shared_in_group=group,  # Será None se não for partilhado com grupo
            shared_with_user=shared_with_user,  # Será None se não for partilhado com user
        )

        # Salva o arquivo encriptado no disco
        path = f'uploads_encrypted/doc_{doc.id}.bin'
        with open(path, 'wb') as f:
            f.write(encrypted)

        # Atualiza o caminho do arquivo no documento
        doc.encrypted_file.name = f'doc_{doc.id}.bin'
        doc.save()

        return Response({
            'id': doc.id,
            'detail': 'File uploaded successfully'
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({'detail': f'Error uploading file: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['POST'])
def signup(request):
    # if request.method == 'POST':
    print(request.data)
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    name = request.data.get('name')
    first_name = name.split(' ')[0] if name else ''
    last_name = ' '.join(name.split(' ')[1:]) if name and len(name.split(' ')) > 1 else ''

    if not username or not email or not password:
        return Response({'detail': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'detail': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'detail': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name
    )
    # user.generate_totp_secret()
    user.save()

    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'name': user.first_name + ' ' + user.last_name,
    }, status=status.HTTP_201_CREATED)


def logout_view(request):
    logout(request)
    return redirect('login')

@api_view(['POST'])
def login_view(request):
    # Com Django REST Framework, use request.data (funciona para JSON e form-data)
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'detail': 'Missing username or password'}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(request, username=username, password=password)
    if user is not None:
        request.session['pre_2fa_user_id'] = user.id
        return Response({
            'id': user.id,
            'requires2FA': bool(user.totp_secret),
        })
        # return Response({
        #     'id': user.id,
        #     'username': user.username,
        #     'name': user.first_name + ' ' + user.last_name,
        #     'email': user.email,
        # })
    return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
# ...existing code...

@api_view(['POST'])
def verify_totp(request):
    user_id = request.data.get('userId')
    if not user_id:
        return Response({'detail': 'Missing userId'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.get(id=user_id)

    if not user.totp_secret:
        return Response({
            'setup2FA': True,
            'detail': 'User is not enrolled in 2FA'
        }, status=status.HTTP_400_BAD_REQUEST)

    code = request.data.get('code')
    totp = pyotp.TOTP(user.totp_secret)
    print(code)
    if totp.verify(code, valid_window=1):
        return Response({
            'id': user.id,
            'username': user.username,
            'name': user.first_name + ' ' + user.last_name,
            'email': user.email,
        })
    else:
        return Response({'error': 'Código TOTP inválido.'}, status=status.HTTP_401_UNAUTHORIZED)



@api_view(['POST'])
def setup_totp(request):
    user_id = request.data.get('user_id')
    user = None
    if user_id:
        user = User.objects.get(id=user_id)
        if not user:
            return redirect('login')

    if not user.totp_secret:
        user.generate_totp_secret()

    uri = user.get_totp_uri()

    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage)
    buffer = BytesIO()
    img.save(buffer)

    # Geração da imagem em PNG e conversão para base64
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return Response(
        {
            'qr_base64': qr_base64,
            'secret': user.totp_secret
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
def user_document_list(request):
    # Obtém o user_id da query string
    user_id = request.query_params.get('user_id')
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Obtém documentos onde o user é owner OU onde o documento foi partilhado com o user
    from django.db.models import Q
    documentos = Document.objects.filter(
        Q(owner=user) | Q(shared_with_user=user)
    )

    # Serializa os documentos
    documentos_data = [
        {
            'id': doc.id,
            'filename': doc.filename,
            'uploaded_at': doc.uploaded_at,
            'file_size': doc.file_size,
            'type': get_file_extension(doc.filename),
            'views': doc.views.count(),
            'likes_count': doc.likes.count(),
            'liked': doc.likes.filter(user=user).exists(),
            'comments_count': doc.comments.count(),
            'last_comments': [
                {
                    'id': comment.id,
                    'content': comment.text,
                    'user': comment.user.username,
                    'author': comment.user.get_full_name(),
                    'user_id': comment.user.id,
                    'date': comment.created_at
                }
                for comment in doc.comments.all()[:3]
            ],
            'owner': doc.owner.username,
            'owner_id': doc.owner.id,
            'is_owner': doc.owner == user,
            'shared_in_group': {
                'id': doc.shared_in_group.id,
                'name': doc.shared_in_group.name
            } if doc.shared_in_group else None,
            'shared_with_user': {
                'id': doc.shared_with_user.id,
                'username': doc.shared_with_user.username,
                'name': doc.shared_with_user.get_full_name()
            } if doc.shared_with_user else None,
        }
        for doc in documentos
    ]

    return Response({
        'user': user.username,
        'documents': documentos_data,
        'count': len(documentos_data)
    }, status=status.HTTP_200_OK)



@api_view(['GET'])
def download_document(request, document_id):
    # Obtém o user_id da query string
    user_id = request.query_params.get('user_id')
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verifica se quer o ficheiro encriptado ou decriptado
    encrypted = request.query_params.get('encrypted', 'false').lower() == 'true'

    try:
        doc = Document.objects.get(id=document_id)

    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o user tem acesso (owner ou shared_with_user)
    if doc.owner != user and doc.shared_with_user != user:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    try:
        path = f'uploads_encrypted/doc_{doc.id}.bin'

        # Ler o ficheiro encriptado
        with open(path, 'rb') as f:
            encrypted_data = f.read()

        if encrypted:
            # Retorna o ficheiro encriptado
            response = HttpResponse(encrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{doc.filename}.bin"'
        else:
            # Desencriptar a chave AES do documento
            aes_key = decrypt_key(doc.encrypted_key, settings.MASTER_KEY)
            # Desencriptar o ficheiro
            decrypted_data = decrypt_file(encrypted_data, aes_key)
            response = HttpResponse(decrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{doc.filename}"'

        return response

    except Exception as e:
        return Response({'detail': f'Error downloading file: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['DELETE'])
def delete_document(request, document_id):
    # Obtém o user_id da query string
    user_id = request.query_params.get('user_id')
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        doc = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o user é o owner do documento
    if doc.owner != user:
        return Response({'detail': 'Permission denied. Only the owner can delete this document.'}, status=status.HTTP_403_FORBIDDEN)

    try:
        # Remove o ficheiro encriptado do disco
        path = f'uploads_encrypted/doc_{doc.id}.bin'
        if os.path.isfile(path):
            os.remove(path)

        # Remove o documento da base de dados
        doc.delete()

        return Response({'detail': 'Document deleted successfully'}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'detail': f'Error deleting document: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def create_group(request):
    """Criar um novo grupo"""
    user_id = request.POST.get('user_id')
    user = User.objects.get(id=user_id)
    if not user:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    print(user_id)
    name = request.POST.get('name')
    description = request.POST.get('description', '')
    category = request.POST.get('category', '')
    image_file = request.FILES.get('image')  # Recebe blob como arquivo

    if not name:
        return Response({'detail': 'Group name is required'}, status=status.HTTP_400_BAD_REQUEST)

    print(name)
    image_path = None
    
    # Processar imagem se fornecida
    if image_file:
        try:
            # Gerar nome único para a imagem
            file_ext = image_file.name.split('.')[-1] if '.' in image_file.name else 'png'
            unique_filename = f'group_{uuid.uuid4()}.{file_ext}'
            image_path = f'groups/{unique_filename}'
            
            # Guardar ficheiro na pasta media
            default_storage.save(image_path, image_file)
        except Exception as e:
            return Response({'detail': f'Error uploading image: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
    print("image uploaded")
    # Criar grupo
    group = Group.objects.create(
        name=name,
        description=description,
        category=category,
        image=image_path,  # Guardar apenas o caminho
        created_by=user
    )

    # Adicionar o owner como administrador
    GroupMember.objects.create(
        group=group,
        user=user,
        role='admin'
    )

    # Construir resposta com membros e roles
    members_list = GroupMember.objects.filter(group=group).select_related('user')
    ordered_members = order_members_with_owner_first(members_list, group)
    
    return Response({
        'id': group.id,
        'name': group.name,
        'description': group.description,
        'category': group.category,
        'image': image_path,
        'created_by': group.created_by.username,
        'created_date': group.created_date,
        'members_count': len(ordered_members),
        'membersList': [{
            'id': gm.user.id, 
            'username': gm.user.username, 
            'name': gm.user.get_full_name(),
            'role': gm.role
        } for gm in ordered_members],
        'isAdmin': True
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def get_groups(request, user_id):
    """Listar todos os grupos com isAdmin baseado no user_id"""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Obter todos os grupos
    all_groups = Group.objects.all()
    
    data = []
    for group in all_groups:
        memberList = GroupMember.objects.filter(group=group).select_related('user')
        ordered_members = order_members_with_owner_first(memberList, group)
        image_url = None
        if group.image:
            # Construir URL completa da imagem
            image_url = f'/media/{group.image}'
        
        # Verificar se o utilizador é admin do grupo
        is_admin = GroupMember.objects.filter(
            group=group, 
            user=user, 
            role='admin'
        ).exists() or group.created_by == user
        
        data.append({
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'category': group.category,
            'image': image_url,
            'createdBy': group.created_by.username,
            'createdDate': group.created_date.isoformat(),
            'members_count': len(ordered_members),
            'memberList': [{
                'id': gm.user.id,
                'username': gm.user.username,
                'email': gm.user.email,
                'name': gm.user.get_full_name(),
                'role': gm.role
            } for gm in ordered_members],
            'isAdmin': is_admin
        })
    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
def list_users(request):
    """Listar todos os utilizadores"""
    users = User.objects.all()

    users_data = [
        {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'name': user.get_full_name(),
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
        for user in users
    ]

    return Response({
        'users': users_data,
        'count': len(users_data)
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_user_profile(request, user_id):
    """Obter perfil do utilizador"""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se existe avatar
    avatar_url = None
    avatar_dir = os.path.join('media', 'avatars')
    allowed_extensions = ['jpg', 'jpeg', 'png']
    for ext in allowed_extensions:
        avatar_path = os.path.join(avatar_dir, f'{user.id}.{ext}')
        if os.path.isfile(avatar_path):
            avatar_url = f'/media/avatars/{user.id}.{ext}'
            break

    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'name': user.get_full_name(),
        'avatar': avatar_url
    }, status=status.HTTP_200_OK)


@api_view(['PUT'])
def update_user_profile(request):
    """Atualizar perfil do utilizador: avatar, nomes e password"""
    user_id = request.data.get('user_id')

    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # ========== Atualizar avatar ==========
    avatar_url = None
    if 'avatar' in request.FILES:
        try:
            avatar_file = request.FILES['avatar']

            # Validar extensão do ficheiro
            allowed_extensions = ['jpg', 'jpeg', 'png']
            file_ext = avatar_file.name.split('.')[-1].lower()

            if file_ext not in allowed_extensions:
                return Response({'detail': 'Only JPG and PNG files are allowed'}, status=status.HTTP_400_BAD_REQUEST)

            # Criar pasta se não existir
            avatar_dir = os.path.join('media', 'avatars')
            os.makedirs(avatar_dir, exist_ok=True)

            # Guardar ficheiro com nome {user_id}.{extensão}
            avatar_path = os.path.join(avatar_dir, f'{user.id}.{file_ext}')

            # Remover avatar antigo se existir (qualquer extensão)
            for ext in allowed_extensions:
                old_path = os.path.join(avatar_dir, f'{user.id}.{ext}')
                if os.path.isfile(old_path):
                    os.remove(old_path)

            # Guardar novo avatar
            with open(avatar_path, 'wb') as f:
                for chunk in avatar_file.chunks():
                    f.write(chunk)

            avatar_url = f'/media/avatars/{user.id}.{file_ext}'
        except Exception as e:
            return Response({'detail': f'Error uploading avatar: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    # ========== Atualizar nomes e email ==========
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    email = request.data.get('email')

    if first_name:
        user.first_name = first_name
    if last_name:
        user.last_name = last_name
    if email:
        # Validar se o email já existe
        if User.objects.filter(email=email).exclude(id=user.id).exists():
            return Response({'detail': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        user.email = email

    # ========== Atualizar password ==========
    current_password = request.data.get('current_password')
    new_password = request.data.get('new_password')

    if current_password and new_password:
        # Verificar se a password atual está correta
        if not user.check_password(current_password):
            return Response({'detail': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

        # Atualizar password
        user.set_password(new_password)

    # Guardar alterações
    user.save()

    # Se não foi enviado avatar, verificar se existe
    if not avatar_url:
        avatar_dir = os.path.join('media', 'avatars')
        allowed_extensions = ['jpg', 'jpeg', 'png']
        for ext in allowed_extensions:
            avatar_path = os.path.join(avatar_dir, f'{user.id}.{ext}')
            if os.path.isfile(avatar_path):
                avatar_url = f'/media/avatars/{user.id}.{ext}'
                break

    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'name': user.get_full_name(),
        'avatar': avatar_url,
        'detail': 'Profile updated successfully'
    }, status=status.HTTP_200_OK)



@api_view(['POST'])
def request_group_access(request):
    """Criar um pedido de acesso a um grupo"""
    user_id = request.data.get('user_id')
    group_id = request.data.get('group_id')
    message = request.data.get('message', '')

    if not user_id or not group_id:
        return Response({'detail': 'User ID and Group ID are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se já é membro
    is_member = GroupMember.objects.filter(group=group, user=user).exists()
    if is_member:
        return Response({'detail': 'User is already a member'}, status=status.HTTP_400_BAD_REQUEST)

    # Verificar se já tem um pedido pendente
    pending_request = RequestAccess.objects.filter(
        group=group, 
        user=user, 
        status='pending'
    ).first()
    
    if pending_request:
        return Response({'detail': 'Request already pending'}, status=status.HTTP_400_BAD_REQUEST)

    # Verificar se há um pedido rejeitado
    rejected_request = RequestAccess.objects.filter(
        group=group, 
        user=user, 
        status='rejected'
    ).first()

    if rejected_request:
        # Alterar o pedido rejeitado para pending
        rejected_request.status = 'pending'
        rejected_request.requested_date = datetime.now()
        rejected_request.responded_date = None
        rejected_request.message = message
        rejected_request.save()
        request_obj = rejected_request
    else:
        # Criar novo pedido
        request_obj = RequestAccess.objects.create(
            user=user,
            group=group,
            message=message
        )

    return Response({
        'id': request_obj.id,
        'user': user.username,
        'group': group.name,
        'status': request_obj.status,
        'requested_date': request_obj.requested_date.isoformat(),
        'message': request_obj.message
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def get_access_requests(request, user_id):
    """Listar pedidos de acesso pendentes de todos os grupos onde o user é admin"""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Obter grupos onde o user é admin ou owner
    admin_groups = Group.objects.filter(
        Q(created_by=user) | 
        Q(group_members__user=user, group_members__role='admin')
    ).distinct()

    # Obter pedidos pendentes desses grupos
    requests_list = RequestAccess.objects.filter(
        group__in=admin_groups,
        status='pending'
    ).select_related('user', 'group')

    data = []
    for req in requests_list:
        data.append({
            'id': req.id,
            'group_id': req.group.id,
            'group_name': req.group.name,
            'user_id': req.user.id,
            'username': req.user.username,
            'user_email': req.user.email,
            'user_name': req.user.get_full_name(),
            'status': req.status,
            'requested_date': req.requested_date.isoformat(),
            'responded_date': req.responded_date.isoformat() if req.responded_date else None,
            'message': req.message
        })

    return Response(data, status=status.HTTP_200_OK)


@api_view(['POST'])
def respond_access_request(request, request_id):
    """Responder a um pedido de acesso (aprovar ou rejeitar)"""
    user_id = request.data.get('user_id')
    action = request.data.get('action')  # 'approve' ou 'reject'

    if not user_id:
        return Response({'detail': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)

    if action not in ['approve', 'reject']:
        return Response({'detail': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        access_request = RequestAccess.objects.get(id=request_id)
    except RequestAccess.DoesNotExist:
        return Response({'detail': 'Request not found'}, status=status.HTTP_404_NOT_FOUND)

    group = access_request.group

    # Verificar se o utilizador é admin do grupo
    is_admin = GroupMember.objects.filter(
        group=group, 
        user=user, 
        role='admin'
    ).exists() or group.created_by == user

    if not is_admin:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    if access_request.status != 'pending':
        return Response({'detail': 'Request already responded'}, status=status.HTTP_400_BAD_REQUEST)

    if action == 'approve':
        # Adicionar user como membro
        GroupMember.objects.create(
            group=group,
            user=access_request.user,
            role='membro'
        )
        access_request.status = 'approved'
    else:
        access_request.status = 'rejected'

    access_request.responded_date = datetime.now()
    access_request.save()

    return Response({
        'id': access_request.id,
        'status': access_request.status,
        'responded_date': access_request.responded_date.isoformat()
    }, status=status.HTTP_200_OK)


@api_view(['PUT'])
def update_member_role(request, group_id):
    """Alterar a role de um membro do grupo"""
    user_id = request.data.get('user_id')
    member_id = request.data.get('member_id')
    new_role = request.data.get('role')

    if not user_id or not member_id or not new_role:
        return Response({'detail': 'User ID, Member ID and Role are required'}, status=status.HTTP_400_BAD_REQUEST)

    if new_role not in ['membro', 'admin', 'moderador']:
        return Response({'detail': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador é admin do grupo
    is_admin = GroupMember.objects.filter(
        group=group, 
        user=user, 
        role='admin'
    ).exists() or group.created_by == user

    if not is_admin:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    try:
        member_user = User.objects.get(id=member_id)
    except User.DoesNotExist:
        return Response({'detail': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        group_member = GroupMember.objects.get(group=group, user=member_user)
    except GroupMember.DoesNotExist:
        return Response({'detail': 'User is not a member of this group'}, status=status.HTTP_404_NOT_FOUND)

    # Atualizar a role
    group_member.role = new_role
    group_member.save()

    return Response({
        'id': group_member.id,
        'user_id': group_member.user.id,
        'username': group_member.user.username,
        'group_id': group_member.group.id,
        'group_name': group_member.group.name,
        'role': group_member.role,
        'joined_date': group_member.joined_date.isoformat()
    }, status=status.HTTP_200_OK)


@api_view(['POST', 'DELETE'])
def manage_group_member(request, group_id):
    """Gerenciar membros do grupo - POST para adicionar, DELETE para remover"""
    user_id = request.data.get('user_id')
    member_id = request.data.get('member_id')

    if not user_id or not member_id:
        return Response({'detail': 'User ID and Member ID are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        member_user = User.objects.get(id=member_id)
    except User.DoesNotExist:
        return Response({'detail': 'Member not found'}, status=status.HTTP_404_NOT_FOUND)

    # ========== DELETE - Remover membro ==========
    if request.method == 'DELETE':
        """Remover um membro do grupo (admin ou o próprio utilizador)"""
        try:
            group_member = GroupMember.objects.get(group=group, user=member_user)
        except GroupMember.DoesNotExist:
            return Response({'detail': 'User is not a member of this group'}, status=status.HTTP_404_NOT_FOUND)

        # Evitar remover o owner do grupo
        if group.created_by == member_user:
            return Response({'detail': 'Cannot remove the group owner'}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar permissões: user_id é admin OU user_id é o próprio membro a ser removido
        is_admin = GroupMember.objects.filter(
            group=group, 
            user=user, 
            role='admin'
        ).exists() or group.created_by == user

        is_removing_self = int(user_id) == int(member_id)

        if not is_admin and not is_removing_self:
            return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        # Remover o membro
        group_member.delete()

        return Response({
            'detail': 'Member removed successfully',
            'group_id': group.id,
            'member_id': member_id
        }, status=status.HTTP_200_OK)

    # ========== POST - Adicionar membro ==========
    elif request.method == 'POST':
        """Adicionar um membro ao grupo (admin e moderador)"""
        role = request.data.get('role', 'membro')  # role padrão é 'membro'

        if role not in ['membro', 'admin', 'moderador']:
            return Response({'detail': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

        # Verificar se o utilizador é admin ou moderador do grupo
        user_group_member = GroupMember.objects.filter(
            group=group, 
            user=user
        ).first()

        is_admin = user_group_member and user_group_member.role == 'admin'
        is_moderator = user_group_member and user_group_member.role == 'moderador'
        is_owner = group.created_by == user

        # Apenas admin, moderador ou owner podem adicionar membros
        if not (is_admin or is_moderator or is_owner):
            return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

        # Verificar se o utilizador já é membro do grupo
        if GroupMember.objects.filter(group=group, user=member_user).exists():
            return Response({'detail': 'User is already a member of this group'}, status=status.HTTP_400_BAD_REQUEST)

        # Criar o novo membro
        group_member = GroupMember.objects.create(
            group=group,
            user=member_user,
            role=role
        )

        return Response({
            'id': group_member.id,
            'user_id': group_member.user.id,
            'username': group_member.user.username,
            'email': group_member.user.email,
            'name': group_member.user.get_full_name(),
            'group_id': group_member.group.id,
            'group_name': group_member.group.name,
            'role': group_member.role,
            'joined_date': group_member.joined_date.isoformat(),
            'detail': 'Member added successfully'
        }, status=status.HTTP_201_CREATED)

    return Response({'detail': 'Invalid request method'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['GET'])
def get_group_documents(request, group_id):
    """Listar todos os documentos de um grupo"""
    user_id = request.query_params.get('user_id')
    
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador é membro do grupo
    is_member = GroupMember.objects.filter(group=group, user=user).exists()
    is_owner = group.created_by == user

    if not is_member and not is_owner:
        return Response({'detail': 'User is not a member of this group'}, status=status.HTTP_403_FORBIDDEN)

    # Obter todos os documentos do grupo
    documents = Document.objects.filter(shared_in_group=group).select_related('owner')

    # Serializa os documentos com mesma estrutura de user_document_list
    documents_data = [
        {
            'id': doc.id,
            'filename': doc.filename,
            'uploaded_at': doc.uploaded_at,
            'file_size': doc.file_size,
            'type': get_file_extension(doc.filename),
            'views': doc.views.count(),
            'likes_count': doc.likes.count(),
            'liked': doc.likes.filter(user=user).exists(),
            'comments_count': doc.comments.count(),
            'last_comments': [
                {
                    'id': comment.id,
                    'content': comment.text,
                    'user': comment.user.username,
                    'author': comment.user.get_full_name(),
                    'user_id': comment.user.id,
                    'date': comment.created_at
                }
                for comment in doc.comments.all()[:3]
            ],
            'owner': doc.owner.username,
            'owner_id': doc.owner.id,
            'is_owner': doc.owner == user,
            'shared_in_group': {
                'id': doc.shared_in_group.id,
                'name': doc.shared_in_group.name
            } if doc.shared_in_group else None,
            'shared_with_user': {
                'id': doc.shared_with_user.id,
                'username': doc.shared_with_user.username,
                'name': doc.shared_with_user.get_full_name()
            } if doc.shared_with_user else None,
        }
        for doc in documents
    ]

    return Response({
        'group': group.name,
        'documents': documents_data,
        'count': len(documents_data)
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_document(request, document_id):
    """Obter informações de um documento pelo ID"""
    user_id = request.query_params.get('user_id')
    
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        doc = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador tem acesso ao documento
    # Pode ser: owner, shared_with_user, ou membro do grupo onde está partilhado
    has_access = False
    
    if doc.owner == user:
        has_access = True
    elif doc.shared_with_user == user:
        has_access = True
    elif doc.shared_in_group:
        # Verificar se é membro do grupo
        is_member = GroupMember.objects.filter(
            group=doc.shared_in_group,
            user=user
        ).exists() or doc.shared_in_group.created_by == user
        if is_member:
            has_access = True

    if not has_access:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    # Retornar informações do documento
    return Response({
        'id': doc.id,
        'filename': doc.filename,
        'uploaded_at': doc.uploaded_at,
        'file_size': doc.file_size,
        'type': get_file_extension(doc.filename),
        'views': doc.views.count(),
        'likes_count': doc.likes.count(),
        'liked': doc.likes.filter(user=user).exists(),
        'comments_count': doc.comments.count(),
        'last_comments': [
                {
                    'id': comment.id,
                    'content': comment.text,
                    'user': comment.user.username,
                    'author': comment.user.get_full_name(),
                    'user_id': comment.user.id,
                    'date': comment.created_at
                }
                for comment in doc.comments.all()[:3]
        ],
        'owner': doc.owner.username,
        'owner_id': doc.owner.id,
        'is_owner': doc.owner == user,
        'shared_in_group': {
            'id': doc.shared_in_group.id,
            'name': doc.shared_in_group.name
        } if doc.shared_in_group else None,
        'shared_with_user': {
            'id': doc.shared_with_user.id,
            'username': doc.shared_with_user.username,
            'name': doc.shared_with_user.get_full_name()
        } if doc.shared_with_user else None,
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def add_document_view(request, document_id):
    from django.utils import timezone
    from datetime import timedelta
    from .models import DocumentView
    
    user_id = request.data.get('user_id')
    
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        doc = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador tem acesso ao documento
    has_access = False
    
    if doc.owner == user:
        has_access = True
    elif doc.shared_with_user == user:
        has_access = True
    elif doc.shared_in_group:
        # Verificar se é membro do grupo
        is_member = GroupMember.objects.filter(
            group=doc.shared_in_group,
            user=user
        ).exists() or doc.shared_in_group.created_by == user
        if is_member:
            has_access = True

    if not has_access:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    # Verificar se o utilizador já viu o documento nesta hora
    now = timezone.now()
    hour_start = now.replace(minute=0, second=0, microsecond=0)
    hour_end = hour_start + timedelta(hours=1)
    
    view_this_hour = DocumentView.objects.filter(
        document=doc,
        user=user,
        viewed_at__gte=hour_start,
        viewed_at__lt=hour_end
    ).first()
    
    if view_this_hour:
        return Response({
            'detail': 'User already viewed this document this hour',
        }, status=status.HTTP_200_OK)
    
    # Registar a visualização
    DocumentView.objects.create(
        document=doc,
        user=user
    )

    return Response({
        'detail': 'View added successfully',
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def toggle_document_like(request, document_id):
    from .models import Like
    
    user_id = request.data.get('user_id')
    
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        doc = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador tem acesso ao documento
    has_access = False
    
    if doc.owner == user:
        has_access = True
    elif doc.shared_with_user == user:
        has_access = True
    elif doc.shared_in_group:
        # Verificar se é membro do grupo
        is_member = GroupMember.objects.filter(
            group=doc.shared_in_group,
            user=user
        ).exists() or doc.shared_in_group.created_by == user
        if is_member:
            has_access = True

    if not has_access:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    # Verificar se já tem like
    like_exists = Like.objects.filter(document=doc, user=user).exists()
    
    if like_exists:
        # Remover o like
        Like.objects.filter(document=doc, user=user).delete()
        return Response({
            'detail': 'Like removed successfully',
            'likes_count': doc.likes.count(),
            'liked': False
        }, status=status.HTTP_200_OK)
    else:
        # Adicionar o like
        Like.objects.create(document=doc, user=user)
        return Response({
            'detail': 'Like added successfully',
            'likes_count': doc.likes.count(),
            'liked': True
        }, status=status.HTTP_200_OK)


@api_view(['POST'])
def create_comment(request, document_id):
    from .models import Comment
    
    user_id = request.data.get('user_id')
    text = request.data.get('text')
    
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not text:
        return Response({'detail': 'Missing comment text'}, status=status.HTTP_400_BAD_REQUEST)
    
    if len(text.strip()) == 0:
        return Response({'detail': 'Comment text cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        doc = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador tem acesso ao documento
    has_access = False
    
    if doc.owner == user:
        has_access = True
    elif doc.shared_with_user == user:
        has_access = True
    elif doc.shared_in_group:
        # Verificar se é membro do grupo
        is_member = GroupMember.objects.filter(
            group=doc.shared_in_group,
            user=user
        ).exists() or doc.shared_in_group.created_by == user
        if is_member:
            has_access = True

    if not has_access:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    # Criar o comentário
    comment = Comment.objects.create(
        document=doc,
        user=user,
        text=text.strip()
    )

    return Response({
        'detail': 'Comment created successfully',
        'comment': {
            'id': comment.id,
            'text': comment.text,
            'user': comment.user.username,
            'user_name': comment.user.get_full_name(),
            'user_id': comment.user.id,
            'created_at': comment.created_at,
            'updated_at': comment.updated_at
        },
        'comments_count': doc.comments.count()
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def list_document_comments(request, document_id):
    user_id = request.query_params.get('user_id')
    
    if not user_id:
        return Response({'detail': 'Missing user_id'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        doc = Document.objects.get(id=document_id)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verificar se o utilizador tem acesso ao documento
    has_access = False
    
    if doc.owner == user:
        has_access = True
    elif doc.shared_with_user == user:
        has_access = True
    elif doc.shared_in_group:
        # Verificar se é membro do grupo
        is_member = GroupMember.objects.filter(
            group=doc.shared_in_group,
            user=user
        ).exists() or doc.shared_in_group.created_by == user
        if is_member:
            has_access = True

    if not has_access:
        return Response({'detail': 'Permission denied'}, status=status.HTTP_403_FORBIDDEN)

    # Obter todos os comentários do documento
    comments = doc.comments.all()

    # Serializar os comentários
    comments_data = [
        {
            'id': comment.id,
            'text': comment.text,
            'user': comment.user.username,
            'user_name': comment.user.get_full_name(),
            'user_id': comment.user.id,
            'created_at': comment.created_at,
            'updated_at': comment.updated_at
        }
        for comment in comments
    ]

    return Response({
        'document_id': doc.id,
        'comments': comments_data,
        'comments_count': len(comments_data)
    }, status=status.HTTP_200_OK)

