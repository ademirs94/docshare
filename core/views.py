from django.shortcuts import redirect
from docshare import settings
from .models import Document, User, Group, GroupMember
from django.contrib.auth import login, authenticate, logout
from django.http import HttpResponse
from .utils import decrypt_file, decrypt_key, encrypt_key, encrypt_file
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
import os
import uuid

from django.core.files.storage import default_storage

from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view

@api_view(['POST'])
def upload_document(request):
    # Obtém o user_id e group_id do formulário
    user_id = request.POST.get('user_id')
    group_id = request.POST.get('group_id')

    # Valida que apenas um dos dois foi fornecido
    if user_id and group_id:
        return Response({'detail': 'Cannot specify both user_id and group_id'}, status=status.HTTP_400_BAD_REQUEST)

    if not user_id and not group_id:
        return Response({'detail': 'Missing user_id or group_id'}, status=status.HTTP_400_BAD_REQUEST)

    user = None
    group = None

    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if group_id:
        try:
            group = Group.objects.get(id=group_id)
            # O owner será o criador do grupo
            user = group.created_by
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

    # Verifica se há arquivo no request
    if 'file' not in request.FILES:
        return Response({'detail': 'Missing file'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Lê os dados do arquivo
        file_obj = request.FILES['file']
        file_data = file_obj.read()

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
            shared_in_group=group,  # Será None se for upload pessoal
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
            'filename': doc.filename,
            'owner': doc.owner.username,
            'uploaded_at': doc.uploaded_at,
            'group_id': doc.shared_in_group.id if doc.shared_in_group else None,
            'group_name': doc.shared_in_group.name if doc.shared_in_group else None,
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

    # Obtém apenas os documentos do utilizador
    documentos = Document.objects.filter(owner=user)

    # Serializa os documentos
    documentos_data = [
        {
            'id': doc.id,
            'filename': doc.filename,
            'uploaded_at': doc.uploaded_at,
            'owner': doc.owner.username,
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
        doc = Document.objects.get(id=document_id, owner=user)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        # Ler o ficheiro encriptado
        with open(doc.encrypted_file.path, 'rb') as f:
            encrypted_data = f.read()

        if encrypted:
            # Retorna o ficheiro encriptado
            response = HttpResponse(encrypted_data, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{doc.filename}.encrypted"'
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
        doc = Document.objects.get(id=document_id, owner=user)
    except Document.DoesNotExist:
        return Response({'detail': 'Document not found'}, status=status.HTTP_404_NOT_FOUND)

    try:
        # Remove o ficheiro encriptado do disco
        if doc.encrypted_file and os.path.isfile(doc.encrypted_file.path):
            os.remove(doc.encrypted_file.path)

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
    
    return Response({
        'id': group.id,
        'name': group.name,
        'description': group.description,
        'category': group.category,
        'image': image_path,
        'created_by': group.created_by.username,
        'created_date': group.created_date,
        'members_count': members_list.count(),
        'membersList': [{
            'id': gm.user.id, 
            'username': gm.user.username, 
            'name': gm.user.get_full_name(),
            'role': gm.role
        } for gm in members_list],
        'isAdmin': True
    }, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def get_groups(request, user_id):
    """Listar grupos onde o user é owner ou member"""
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Obter todos os grupos
    all_groups = Group.objects.all()
    
    # Filtrar grupos onde o user é owner ou member
    user_groups = []
    for group in all_groups:
        is_owner = group.created_by == user
        is_member = GroupMember.objects.filter(group=group, user=user).exists()
        
        if is_owner or is_member:
            user_groups.append(group)
    
    data = []
    for group in user_groups:
        memberList = GroupMember.objects.filter(group=group).select_related('user')
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
            'members_count': memberList.count(),
            'memberList': [{
                'id': gm.user.id,
                'username': gm.user.username,
                'name': gm.user.get_full_name(),
                'role': gm.role
            } for gm in memberList],
            'isAdmin': is_admin
        })
    return Response(data, status=status.HTTP_200_OK)
