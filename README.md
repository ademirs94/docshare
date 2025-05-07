# Docshare

## 📦 Manual de Instalação

### 1. Requisitos Mínimos

Antes de instalar o sistema, garantir os seguintes requisitos:

- Python 3.10 ou superior  
- `pip` (gestor de pacotes do Python)  
- Git (opcional)  
- Sistema operativo: Windows, Linux ou macOS  
- Navegador web moderno (Chrome, Firefox, etc.)  
- IDE para desenvolvimento (opcional)  

---

### 2. Instalação

#### 2.1. Via repositório GIT

```bash
git clone https://github.com/ademirs94/docshare.git
cd docshare
```
![image](https://github.com/user-attachments/assets/cc8db410-93b9-4e21-b0af-3be6ad024d8c)


#### 2.2. Criar ambiente virtual (opcional mas recomendado)
##### Linux/macOS
```bash
python -m venv venv
source venv/bin/activate
````

##### Windows
```bash
python -m venv venv
venv\Scripts\activate
````
![image](https://github.com/user-attachments/assets/ec15d5d2-5d6b-4c88-92c0-58f2386dad06)

#### 2.3. Instalar dependências
```bash
pip install -r requirements.txt
```
![image](https://github.com/user-attachments/assets/a2b6c0fd-97b5-4bbb-aa3a-c8e879e917a0)


### 3. Configuração Inicial

#### 3.1. Definir a chave mestra de encriptação
No ficheiro docshare/settings.py, linha 37:
```python
MASTER_KEY = b'minha_chave_segura_de_32_bytes'
```

#### 3.2. Configurar base de dados
No mesmo ficheiro, linha 84, definir o caminho para o servidor da base de dados.
![image](https://github.com/user-attachments/assets/1cbb854e-599d-460b-a3ad-c5f1fcc480da)


#### 3.3. Criar/Atualizar a base de dados
```bash
python manage.py makemigrations core
python manage.py migrate core
python manage.py migrate
```
![image](https://github.com/user-attachments/assets/f85b7044-0696-4264-b054-edffa9310e09)


#### 3.4. Criar superutilizador (administrador)
```bash
python manage.py createsuperuser --username admin --email admin@example.com
```
![image](https://github.com/user-attachments/assets/9415326a-7174-4134-9398-225b92e17da1)


### 4. Execução do Servidor
```bash
python manage.py runserver
```
![image](https://github.com/user-attachments/assets/a5464638-c293-46ea-90ea-68fbf890684d)

Acede a http://localhost:8000 no navegador.



## 🧭 Manual de Utilização

### 1. Registo de Utilizadores

- Aceder à página inicial.
- Clicar em "Criar nova conta".

  ![image](https://github.com/user-attachments/assets/de125b71-6099-4de9-9da5-9155aabda133)

  
- Preencher os dados obrigatórios e submeter.

  ![image](https://github.com/user-attachments/assets/c77e6abc-62f5-4d43-a4ef-fc87208b6f19)

- Configurar a autenticação de dois fatores (2FA) através de um código QR ou introdução manual com uma app como o Google Authenticator.

  ![image](https://github.com/user-attachments/assets/11ddaaa4-71d3-40ac-95a0-a2759ca6ed3c)

---

### 2. Login

- Introduzir nome de utilizador e palavra-passe.
- Introduzir o código 2FA gerado pela aplicação.

  ![image](https://github.com/user-attachments/assets/8393ba62-cfcc-4dd8-85b3-36ab611cfba2)

- Após a autenticação, o utilizador é redirecionado para a página "Meus Documentos".
  - Colaboradores veem apenas os seus documentos.  
  - Gestores têm acesso a todos os documentos da empresa.

  ![image](https://github.com/user-attachments/assets/d3397401-5d09-4813-8ef9-6d419ceae257)

---

### 3. Upload de Documentos

- Na página "Meus Documentos", clicar em "Adicionar Documentos".
- Selecionar o ficheiro desejado.
- Submeter o formulário.
- O sistema encripta automaticamente o ficheiro com AES-256 e armazena-o no servidor.

  ![image](https://github.com/user-attachments/assets/45075a99-16e6-45ca-adab-1f8ea7187f01)

---

### 4. Download de Documentos

- Aceder à lista de documentos.
- Clicar no botão "Download" junto ao ficheiro desejado.

  ![image](https://github.com/user-attachments/assets/2410260f-76f6-4e5c-9393-199e9c865552)

- O sistema desencripta o ficheiro e inicia a transferência.

  ![image](https://github.com/user-attachments/assets/ad23851b-321f-4198-820e-81ed88debfed)


---

### 5. Logout

- Clicar no botão "Logout" na barra de navegação superior.

  ![image](https://github.com/user-attachments/assets/3f0034f8-4f7e-40bf-a2d7-eedd1d082418)


---

### 6. Privilégios de Administrador

- Pode aceder a todos os documentos.
- Pode eliminar documentos de qualquer utilizador.

  ![image](https://github.com/user-attachments/assets/062381d4-26ee-4216-b226-30c519548998)


---

### 7. Segurança

- Cada ficheiro é encriptado com uma chave única (AES-256).
- As chaves dos ficheiros são protegidas com uma MASTER_KEY.
- A autenticação de dois fatores (2FA) é obrigatória para todos os utilizadores.


