from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

from docshare import settings
from .forms import DocumentUploadForm
from .models import Document, User
from .forms import SignUpForm
from django.contrib.auth import login, authenticate, logout

from django.http import HttpResponse, Http404
from .utils import decrypt_file, decrypt_key, encrypt_key, encrypt_file
import pyotp
import qrcode
import qrcode.image.svg
from io import BytesIO
import base64
import os

@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            file_data = request.FILES['file'].read()
            key, encrypted = encrypt_file(file_data)

            # Encripta a chave com a chave mestra
            encrypted_key = encrypt_key(key, settings.MASTER_KEY)

            doc = Document.objects.create(
                owner=request.user,
                filename=request.FILES['file'].name,
                encrypted_file=None,
                encrypted_key=encrypted_key,
            )

            path = f'uploads_encrypted/doc_{doc.id}.bin'
            with open(path, 'wb') as f:
                f.write(encrypted)

            doc.encrypted_file.name = f'doc_{doc.id}.bin'
            doc.save()
            return redirect('upload_success')
    else:
        form = DocumentUploadForm()
    return render(request, 'upload.html', {'form': form})




def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.generate_totp_secret()
            user.save()
            login(request, user)
            return redirect('setup_totp')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('login')

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            request.session['pre_2fa_user_id'] = user.id
            return redirect('verify_totp')
        else:
            return render(request, 'login.html', {'error': 'Credenciais inválidas.'})
    return render(request, 'login.html')


def verify_totp(request):
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('login')

    user = User.objects.get(id=user_id)

    if not user.totp_secret:
        return redirect('setup_totp')

    if request.method == 'POST':
        code = request.POST.get('code')
        totp = pyotp.TOTP(user.totp_secret)
        print(code)
        if totp.verify(code):
            login(request, user)
            del request.session['pre_2fa_user_id']
            return redirect('document_list')  # ou a tua página principal
        else:
            return render(request, 'verify_totp.html', {'error': 'Código TOTP inválido.'})

    return render(request, 'verify_totp.html')


# @login_required
def setup_totp(request):
    user = request.user
    user_id = request.session.get('pre_2fa_user_id')
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
    svg = buffer.getvalue().decode()

    # Geração da imagem em PNG e conversão para base64
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    return render(request, 'setup_totp.html', {
        'svg': svg,
        'qr_base64': qr_base64,
        'secret': user.totp_secret
    })


@login_required
def document_list(request):
    # Verifica se o utilizador é um gestor
    if request.user.role == 'gestor' or request.user.is_superuser:
        # Gestores podem ver todos os documentos
        documentos = Document.objects.all()
    else:
        # Outros utilizadores veem apenas os seus próprios documentos
        documentos = Document.objects.filter(owner=request.user)

    return render(request, 'document_list.html', {'documentos': documentos})



@login_required
def download_document(request, document_id):
    try:
        doc = Document.objects.get(id=document_id, owner=request.user)
    except Document.DoesNotExist:
        raise Http404("Documento não encontrado.")

    # Desencriptar a chave AES do documento
    encrypted_key = doc.encrypted_key  # BinaryField ou base64.decode, conforme guardado
    aes_key = decrypt_key(encrypted_key, settings.MASTER_KEY)

    # Ler o ficheiro encriptado
    with open(doc.encrypted_file.path, 'rb') as f:
        encrypted_data = f.read()

    # Desencriptar o ficheiro com a chave obtida
    decrypted_data = decrypt_file(encrypted_data, aes_key)

    response = HttpResponse(decrypted_data, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename="{doc.filename}"'
    return response


@login_required
def delete_document(request, document_id):
    doc = get_object_or_404(Document, id=document_id)

    if request.user.is_superuser:
        if doc.encrypted_file and os.path.isfile(doc.encrypted_file.path):
            os.remove(doc.encrypted_file.path)
        doc.delete()


    return redirect('document_list')
