# =============================================================================
# TESTES AUTOMATIZADOS PARA O SISTEMA SAR
# =============================================================================

# tests/conftest.py - Configuração base para testes
import pytest
import tempfile
import os
from app import create_app, db, Usuario, Processo
from werkzeug.security import generate_password_hash

@pytest.fixture
def app():
    """Criar aplicação de teste"""
    # Criar banco temporário
    db_fd, db_path = tempfile.mkstemp()
    
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        
        # Criar usuários de teste
        admin = Usuario(
            primeiro_nome='admin',
            papel='admin',
            email='admin@test.com',
            ativo=True
        )
        admin.set_senha('admin123')
        
        gerente = Usuario(
            primeiro_nome='gerente',
            papel='gerente', 
            email='gerente@test.com',
            ativo=True
        )
        gerente.set_senha('gerente123')
        
        analista = Usuario(
            primeiro_nome='analista',
            papel='analista',
            email='analista@test.com', 
            ativo=True
        )
        analista.set_senha('analista123')
        
        db.session.add_all([admin, gerente, analista])
        db.session.commit()
        
        yield app
        
        # Cleanup
        db.session.remove()
        db.drop_all()
        os.close(db_fd)
        os.unlink(db_path)

@pytest.fixture
def client(app):
    """Cliente de teste"""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Runner CLI"""
    return app.test_cli_runner()

@pytest.fixture
def auth_headers():
    """Headers de autenticação"""
    return {'Content-Type': 'application/json'}

# =============================================================================
# TESTES DE AUTENTICAÇÃO
# =============================================================================

# tests/test_auth.py
def test_login_page(client):
    """Testar página de login"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data

def test_valid_login(client):
    """Testar login válido"""
    response = client.post('/login', data={
        'primeiro_nome': 'admin',
        'senha': 'admin123'
    })
    assert response.status_code == 302  # Redirect

def test_invalid_login(client):
    """Testar login inválido"""
    response = client.post('/login', data={
        'primeiro_nome': 'admin',
        'senha': 'senha_errada'
    })
    assert response.status_code == 200
    assert b'inv\xc3\xa1lidas' in response.data  # 'inválidas' em UTF-8

def test_logout(client):
    """Testar logout"""
    # Login primeiro
    client.post('/login', data={
        'primeiro_nome': 'admin', 
        'senha': 'admin123'
    })
    
    # Logout
    response = client.get('/logout')
    assert response.status_code == 302  # Redirect para login

def test_access_without_login(client):
    """Testar acesso sem login"""
    response = client.get('/dashboard')
    assert response.status_code == 302  # Redirect para login

# =============================================================================
# TESTES DE API
# =============================================================================

# tests/test_api.py
def login_user(client, username='admin', password='admin123'):
    """Helper para fazer login"""
    return client.post('/login', data={
        'primeiro_nome': username,
        'senha': password
    })

def test_criar_processo_api(client):
    """Testar criação de processo via API"""
    # Login como gerente
    login_user(client, 'gerente', 'gerente123')
    
    # Dados do processo
    data = {
        'numero': 'PROC-2025-001',
        'titulo': 'Processo de Teste',
        'descricao': 'Descrição do processo de teste',
        'prioridade': 'alta',
        'analista_nome': 'analista'
    }
    
    response = client.post('/api/processo/criar', 
                          json=data,
                          headers={'Content-Type': 'application/json'})
    
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True
    assert 'processo' in json_data

def test_criar_processo_duplicado(client):
    """Testar criação de processo com número duplicado"""
    login_user(client, 'gerente', 'gerente123')
    
    data = {
        'numero': 'PROC-DUP-001',
        'titulo': 'Primeiro Processo',
        'prioridade': 'media'
    }
    
    # Criar primeiro processo
    response1 = client.post('/api/processo/criar', json=data)
    assert response1.status_code == 200
    
    # Tentar criar processo duplicado
    response2 = client.post('/api/processo/criar', json=data)
    assert response2.status_code == 400
    json_data = response2.get_json()
    assert json_data['success'] == False

def test_atualizar_processo_api(client, app):
    """Testar atualização de processo via API"""
    login_user(client, 'analista', 'analista123')
    
    with app.app_context():
        # Criar processo diretamente no banco
        gerente = Usuario.query.filter_by(primeiro_nome='gerente').first()
        analista = Usuario.query.filter_by(primeiro_nome='analista').first()
        
        processo = Processo(
            numero='PROC-UPDATE-001',
            titulo='Processo para Atualizar',
            gerente_id=gerente.id,
            analista_id=analista.id
        )
        db.session.add(processo)
        db.session.commit()
        processo_id = processo.id
    
    # Atualizar processo
    data = {
        'status': 'em_analise',
        'observacoes': 'Processo em análise'
    }
    
    response = client.put(f'/api/processo/{processo_id}/atualizar', json=data)
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True

def test_atribuir_processo_api(client, app):
    """Testar atribuição de processo via API"""
    login_user(client, 'gerente', 'gerente123')
    
    with app.app_context():
        # Criar processo sem analista
        gerente = Usuario.query.filter_by(primeiro_nome='gerente').first()
        
        processo = Processo(
            numero='PROC-ATTR-001',
            titulo='Processo para Atribuir',
            gerente_id=gerente.id
        )
        db.session.add(processo)
        db.session.commit()
        processo_id = processo.id
    
    # Atribuir processo
    data = {'analista_nome': 'analista'}
    
    response = client.post(f'/api/processo/{processo_id}/atribuir', json=data)
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True

def test_health_check_api(client):
    """Testar health check"""
    response = client.get('/health/status')
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'status' in json_data
    assert 'timestamp' in json_data

def test_stats_api(client):
    """Testar API de estatísticas"""
    login_user(client, 'admin', 'admin123')
    
    response = client.get('/api/stats')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True
    assert 'stats' in json_data

# =============================================================================
# TESTES DE PERMISSÕES
# =============================================================================

# tests/test_permissions.py
def test_analista_nao_pode_criar_processo(client):
    """Analista não pode criar processo"""
    login_user(client, 'analista', 'analista123')
    
    data = {
        'numero': 'PROC-FAIL-001',
        'titulo': 'Não deve funcionar'
    }
    
    response = client.post('/api/processo/criar', json=data)
    assert response.status_code == 403  # Forbidden

def test_analista_so_ve_seus_processos(client, app):
    """Analista só vê seus próprios processos"""
    with app.app_context():
        gerente = Usuario.query.filter_by(primeiro_nome='gerente').first()
        analista1 = Usuario.query.filter_by(primeiro_nome='analista').first()
        
        # Criar segundo analista
        analista2 = Usuario(
            primeiro_nome='analista2',
            papel='analista',
            email='analista2@test.com',
            ativo=True
        )
        analista2.set_senha('analista123')
        db.session.add(analista2)
        db.session.commit()
        
        # Criar processos para cada analista
        processo1 = Processo(
            numero='PROC-A1-001',
            titulo='Processo Analista 1',
            gerente_id=gerente.id,
            analista_id=analista1.id
        )
        
        processo2 = Processo(
            numero='PROC-A2-001', 
            titulo='Processo Analista 2',
            gerente_id=gerente.id,
            analista_id=analista2.id
        )
        
        db.session.add_all([processo1, processo2])
        db.session.commit()
    
    # Login como analista1
    login_user(client, 'analista', 'analista123')
    
    # Tentar atualizar processo do analista2
    response = client.put(f'/api/processo/{processo2.id}/atualizar', 
                         json={'observacoes': 'Hack attempt'})
    assert response.status_code == 403

def test_gerente_pode_ver_todos_processos(client, app):
    """Gerente pode ver todos os processos"""
    login_user(client, 'gerente', 'gerente123')
    
    response = client.get('/dashboard')
    assert response.status_code == 200

# =============================================================================
# TESTES DE INTEGRAÇÃO
# =============================================================================

# tests/test_integration.py
def test_fluxo_completo_processo(client, app):
    """Testar fluxo completo de um processo"""
    
    # 1. Gerente cria processo
    login_user(client, 'gerente', 'gerente123')
    
    data = {
        'numero': 'PROC-FLUXO-001',
        'titulo': 'Processo Fluxo Completo',
        'descricao': 'Teste de fluxo completo',
        'prioridade': 'alta'
    }
    
    response = client.post('/api/processo/criar', json=data)
    assert response.status_code == 200
    processo_data = response.get_json()['processo']
    processo_id = processo_data['id']
    
    # 2. Gerente atribui processo
    response = client.post(f'/api/processo/{processo_id}/atribuir',
                          json={'analista_nome': 'analista'})
    assert response.status_code == 200
    
    # 3. Analista faz login e atualiza processo
    login_user(client, 'analista', 'analista123')
    
    response = client.put(f'/api/processo/{processo_id}/atualizar',
                         json={'status': 'em_analise', 'observacoes': 'Iniciando análise'})
    assert response.status_code == 200
    
    # 4. Analista adiciona comentário
    response = client.post(f'/api/processo/{processo_id}/comentario',
                          json={'comentario': 'Análise em andamento'})
    assert response.status_code == 200
    
    # 5. Analista conclui processo
    response = client.put(f'/api/processo/{processo_id}/atualizar',
                         json={'status': 'concluido'})
    assert response.status_code == 200
    
    # 6. Verificar estado final
    with app.app_context():
        processo = Processo.query.get(processo_id)
        assert processo.status == 'concluido'
        assert processo.data_conclusao is not None

def test_distribuicao_inteligente(client, app):
    """Testar distribuição inteligente de processos"""
    login_user(client, 'gerente', 'gerente123')
    
    # Criar múltiplos processos
    processo_ids = []
    for i in range(5):
        data = {
            'numero': f'PROC-DIST-{i:03d}',
            'titulo': f'Processo Distribuição {i}',
            'prioridade': 'media'
        }
        response = client.post('/api/processo/criar', json=data)
        assert response.status_code == 200
        processo_ids.append(response.get_json()['processo']['id'])
    
    # Distribuir automaticamente
    response = client.post('/sar/api/distribuicao-inteligente',
                          json={'processo_ids': processo_ids})
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True

# =============================================================================
# TESTES DE PERFORMANCE
# =============================================================================

# tests/test_performance.py
import time

def test_response_time_dashboard(client):
    """Testar tempo de resposta do dashboard"""
    login_user(client, 'gerente', 'gerente123')
    
    start_time = time.time()
    response = client.get('/dashboard')
    end_time = time.time()
    
    assert response.status_code == 200
    assert (end_time - start_time) < 2.0  # Menos de 2 segundos

def test_response_time_api_stats(client):
    """Testar tempo de resposta da API de stats"""
    login_user(client, 'admin', 'admin123')
    
    start_time = time.time()
    response = client.get('/api/stats')
    end_time = time.time()
    
    assert response.status_code == 200
    assert (end_time - start_time) < 1.0  # Menos de 1 segundo

def test_criar_muitos_processos(client, app):
    """Testar criação de muitos processos"""
    login_user(client, 'gerente', 'gerente123')
    
    start_time = time.time()
    
    # Criar 50 processos
    for i in range(50):
        data = {
            'numero': f'PROC-PERF-{i:03d}',
            'titulo': f'Processo Performance {i}',
            'prioridade': 'baixa'
        }
        response = client.post('/api/processo/criar', json=data)
        assert response.status_code == 200
    
    end_time = time.time()
    
    # Não deve demorar mais de 30 segundos
    assert (end_time - start_time) < 30.0
    
    # Verificar se todos foram criados
    with app.app_context():
        count = Processo.query.filter(Processo.numero.like('PROC-PERF-%')).count()
        assert count == 50

# =============================================================================
# TESTES DE BACKUP E SEGURANÇA
# =============================================================================

# tests/test_backup.py
def test_backup_manual_api(client):
    """Testar backup manual via API"""
    login_user(client, 'admin', 'admin123')
    
    response = client.post('/api/backup/manual')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True

def test_verificacao_integridade(client):
    """Testar verificação de integridade"""
    login_user(client, 'admin', 'admin123')
    
    response = client.post('/sar/api/verificacao-integridade')
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data['success'] == True
    assert 'relatorio' in json_data

def test_webhook_security(client):
    """Testar segurança do webhook"""
    # Tentar acessar webhook sem token
    response = client.post('/api/integracao/webhook', json={'teste': 'dados'})
    assert response.status_code == 401
    
    # Tentar com token inválido
    headers = {'Authorization': 'Bearer token_invalido'}
    response = client.post('/api/integracao/webhook', 
                          json={'teste': 'dados'}, 
                          headers=headers)
    assert response.status_code == 401

# =============================================================================
# SETUP DE TESTE COM COVERAGE
# =============================================================================

# pytest.ini
"""
[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = 
    --verbose
    --cov=app
    --cov-report=html
    --cov-report=term-missing
    --cov-fail-under=80
"""

# requirements-dev.txt
"""
pytest>=7.0.0
pytest-flask>=1.2.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
factory-boy>=3.2.1
faker>=18.0.0
coverage>=7.0.0
"""

# =============================================================================
# SCRIPT PARA EXECUTAR TESTES
# =============================================================================

# run_tests.sh
"""
#!/bin/bash

echo "🧪 Executando testes do Sistema SAR..."

# Verificar se está no ambiente virtual
if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "Ative o ambiente virtual primeiro!"
    echo "source venv/bin/activate"
    exit 1
fi

# Instalar dependências de teste
pip install -r requirements-dev.txt

# Definir variáveis de ambiente para teste
export FLASK_ENV=testing
export SECRET_KEY=test-secret-key
export DATABASE_URL=sqlite:///:memory:

# Executar testes
echo "Executando testes unitários..."
pytest tests/ -v --cov=app --cov-report=html --cov-report=term-missing

# Verificar coverage
echo ""
echo "📊 Relatório de cobertura gerado em htmlcov/index.html"

# Executar testes de carga (opcional)
if command -v locust &> /dev/null; then
    echo ""
    echo "🔥 Executar testes de carga? (y/n)"
    read -r resposta
    if [[ "$resposta" == "y" ]]; then
        echo "Iniciando testes de carga com Locust..."
        locust -f tests/load_test.py --host=http://localhost:5000
    fi
fi

echo "✅ Testes concluídos!"
"""

# =============================================================================
# TESTE DE CARGA COM LOCUST
# =============================================================================

# tests/load_test.py
"""
from locust import HttpUser, task, between

class SARUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        # Login
        self.client.post("/login", data={
            "primeiro_nome": "admin",
            "senha": "admin123"
        })
    
    @task(3)
    def view_dashboard(self):
        self.client.get("/dashboard")
    
    @task(2)
    def view_health_check(self):
        self.client.get("/health/status")
    
    @task(1)
    def view_stats(self):
        self.client.get("/api/stats")
    
    @task(1)
    def create_process(self):
        import random
        self.client.post("/api/processo/criar", json={
            "numero": f"PROC-LOAD-{random.randint(1000, 9999)}",
            "titulo": "Processo de teste de carga",
            "prioridade": "media"
        })
"""

print("✅ Suite de testes automatizados criada!")
print("")
print("Para executar os testes:")
print("1. Instale dependências: pip install -r requirements-dev.txt") 
print("2. Execute: chmod +x run_tests.sh && ./run_tests.sh")
print("3. Veja cobertura em: htmlcov/index.html")
print("")
print("Testes incluem:")
print("- Autenticação e autorização")
print("- APIs REST completas") 
print("- Permissões por papel")
print("- Fluxos de integração")
print("- Performance e carga")
print("- Backup e segurança")
print("- Cobertura de código")