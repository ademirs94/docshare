# DocShare - Aplicação de Partilha Segura de Ficheiros - Backend

Uma aplicação web moderna para partilha segura de ficheiros, permitindo o envio de documentos a utilizadores específicos ou a grupos temáticos. Os grupos possuem categorias próprias e funcionam como espaços de colaboração, onde os ficheiros partilhados podem receber comentários e "likes".

## 🎯 Funcionalidades Principais

- **Envio de Ficheiros Individualmente**: Upload seguro de documentos com encriptação automática
- **Criação de Grupos Temáticos**: Organize grupos por categoria para melhor colaboração
- **Partilha com Membros**: Partilhe ficheiros apenas com membros específicos do grupo
- **Comentários e Reações**: Colabore deixando comentários e dando "likes" nos ficheiros
- **Sistema de Controlo de Acessos**: Gerenciamento de permissões de grupo
- **Interface Responsiva**: Funciona perfeitamente em desktop, tablet e mobile

## 🚀 Começar

### Pré-requisitos

- Python 3.10 ou superior
- `pip`
- `git`

### Instalação

1. Clone o repositório

```bash
git clone https://github.com/ademirs94/docshare.git
cd docshare
```

2. Criar ambiente virtual (opcional mas recomendado)

**Linux/macOS**
```bash
python -m venv venv
source venv/bin/activate
```

**Windows**
```bash
python -m venv venv
venv\Scripts\activate
```

3. Instalar dependências

```bash
pip install -r requirements.txt
```

### Configuração Inicial

1. Definir a chave mestra de encriptação

No ficheiro `docshare/settings.py`, linha 37:
```python
MASTER_KEY = b'minha_chave_segura_de_32_bytes'
```

2. Configurar base de dados

No mesmo ficheiro, linha 84, definir o caminho para o servidor da base de dados.

3. Criar/Atualizar a base de dados

```bash
python manage.py makemigrations 
python manage.py migrate
```

4. Execução do Servidor

```bash
python manage.py runserver
```

O servidor estará disponível em `http://127.0.0.1:8000/`





