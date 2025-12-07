# Docshare

## Projeto académico sobre Sistemas de Segurança na Informação.
O ambito deste projeto é de criar uma aplicação que suporte forte autenticação de utilizadores, com tecnologia TOTP para providenciar autenticação com 2 Fatores.
Carregar e encriptar ficheiros de forma segura garantindo a sua confidencialidade.
A encriptação é feita com algoritmo AES-256 com uma Key (32Bytes) auto gerada e novamente encriptada para cada ficheiro.
No download a Key é novamente decriptada e posteriormente usada para decriptar os dados do ficheiro.
As Keys de ficheiros são encriptadas com uma outra MASTER_KEY que é configurada ao nivel da aplicação.


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
python manage.py makemigrations 
python manage.py migrate
```
![image](https://github.com/user-attachments/assets/f85b7044-0696-4264-b054-edffa9310e09)


#### 3.4. Criar superutilizador admin (opcional)
```bash
python manage.py createsuperuser --username admin --email admin@example.com
```
![image](https://github.com/user-attachments/assets/9415326a-7174-4134-9398-225b92e17da1)


### 4. Execução do Servidor
```bash
python manage.py runserver
```
![image](https://github.com/user-attachments/assets/a5464638-c293-46ea-90ea-68fbf890684d)





