import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# CONFIGURAÇÃO BÁSICA
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sar-secret-key-change-in-production'
app.config['DATABASE'] = 'sar.db'

# =============================================================================
# BANCO DE DADOS SIMPLES
# =============================================================================

def init_db():
    """Inicializar banco de dados SQLite"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            primeiro_nome TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            papel TEXT NOT NULL DEFAULT 'analista',
            ativo BOOLEAN DEFAULT 1,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS processos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero TEXT UNIQUE NOT NULL,
            titulo TEXT NOT NULL,
            descricao TEXT,
            status TEXT DEFAULT 'novo',
            prioridade TEXT DEFAULT 'media',
            gerente_id INTEGER,
            analista_id INTEGER,
            observacoes TEXT,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_conclusao TIMESTAMP,
            FOREIGN KEY (gerente_id) REFERENCES usuarios (id),
            FOREIGN KEY (analista_id) REFERENCES usuarios (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db():
    """Obter conexão com banco"""
    return sqlite3.connect(app.config['DATABASE'])

def criar_usuarios_padrao():
    """Criar usuários padrão"""
    usuarios = [
        ('admin', 'admin', 'admin123'),
        ('Erica', 'gerente', '1234'),
        ('Bruno', 'analista', '1234'),
        ('Vanessa', 'analista', '1234'),
        ('Alessandro', 'analista', '1234'),
        ('Carmen', 'analista', '1234'),
        ('Zenilda', 'analista', '1234'),
    ]
    
    conn = get_db()
    for nome, papel, senha in usuarios:
        # Verificar se já existe
        cursor = conn.execute('SELECT id FROM usuarios WHERE primeiro_nome = ?', (nome,))
        if not cursor.fetchone():
            senha_hash = generate_password_hash(senha)
            conn.execute(
                'INSERT INTO usuarios (primeiro_nome, papel, senha_hash) VALUES (?, ?, ?)',
                (nome, papel, senha_hash)
            )
            print(f"✓ Usuário criado: {nome} ({papel})")
        else:
            # Atualizar senha
            senha_hash = generate_password_hash(senha)
            conn.execute(
                'UPDATE usuarios SET senha_hash = ?, papel = ? WHERE primeiro_nome = ?',
                (senha_hash, papel, nome)
            )
            print(f"✓ Usuário atualizado: {nome}")
    
    conn.commit()
    conn.close()

# =============================================================================
# AUTENTICAÇÃO SIMPLES
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            conn = get_db()
            cursor = conn.execute('SELECT papel FROM usuarios WHERE id = ?', (session['user_id'],))
            user = cursor.fetchone()
            conn.close()
            
            if not user or user[0] not in roles:
                flash('Acesso negado.', 'error')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_current_user():
    """Obter usuário atual"""
    if 'user_id' not in session:
        return None
    
    conn = get_db()
    cursor = conn.execute(
        'SELECT id, primeiro_nome, papel FROM usuarios WHERE id = ?', 
        (session['user_id'],)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'primeiro_nome': user[1],
            'papel': user[2]
        }
    return None

# =============================================================================
# TEMPLATES SIMPLIFICADOS
# =============================================================================

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAR - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    <div class="container">
        <div class="row justify-content-center align-items-center min-vh-100">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-header text-center bg-primary text-white">
                        <h4><i class="fas fa-building me-2"></i>Sistema SAR</h4>
                        <p class="mb-0">Setor de Arrecadação</p>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                                        {{ message }}
                                    </div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">Primeiro Nome</label>
                                <input type="text" name="primeiro_nome" class="form-control" required autofocus>
                                <div class="form-text">Ex: Bruno, Vanessa, Erica...</div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Senha</label>
                                <input type="password" name="senha" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                <i class="fas fa-sign-in-alt me-2"></i>Entrar
                            </button>
                        </form>
                    </div>
                    <div class="card-footer text-center text-muted">
                        <small>Usuários: admin/admin123, Erica/1234, Bruno/1234...</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard SAR</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .priority-critica { border-left: 4px solid #dc3545; }
        .priority-alta { border-left: 4px solid #fd7e14; }
        .priority-media { border-left: 4px solid #ffc107; }
        .priority-baixa { border-left: 4px solid #28a745; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-building me-2"></i>SAR - Dashboard
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    <i class="fas fa-user me-1"></i>{{ current_user.primeiro_nome }} ({{ current_user.papel }})
                </span>
                <a class="btn btn-outline-light btn-sm" href="/logout">
                    <i class="fas fa-sign-out-alt me-1"></i>Sair
                </a>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
            <button class="btn btn-primary" onclick="novoProcesso()">
                <i class="fas fa-plus me-2"></i>Novo Processo
            </button>
        </div>

        <!-- Estatísticas -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card text-center border-primary">
                    <div class="card-body">
                        <i class="fas fa-folder-open fa-2x text-primary mb-2"></i>
                        <h3 class="text-primary">{{ stats.total }}</h3>
                        <p class="card-text">Total</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center border-warning">
                    <div class="card-body">
                        <i class="fas fa-clock fa-2x text-warning mb-2"></i>
                        <h3 class="text-warning">{{ stats.pendentes }}</h3>
                        <p class="card-text">Pendentes</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center border-success">
                    <div class="card-body">
                        <i class="fas fa-check-circle fa-2x text-success mb-2"></i>
                        <h3 class="text-success">{{ stats.concluidos }}</h3>
                        <p class="card-text">Concluídos</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center border-info">
                    <div class="card-body">
                        <i class="fas fa-inbox fa-2x text-info mb-2"></i>
                        <h3 class="text-info">{{ stats.nao_atribuidos }}</h3>
                        <p class="card-text">Não Atribuídos</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Processos Não Atribuídos -->
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-inbox me-2"></i>Processos Não Atribuídos</h5>
            </div>
            <div class="card-body">
                {% if processos_nao_atribuidos %}
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Número</th>
                                <th>Título</th>
                                <th>Prioridade</th>
                                <th>Criado em</th>
                                <th>Ações</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for p in processos_nao_atribuidos %}
                            <tr class="priority-{{ p.prioridade }}">
                                <td><strong>{{ p.numero }}</strong></td>
                                <td>{{ p.titulo }}</td>
                                <td>
                                    <span class="badge bg-secondary">{{ p.prioridade }}</span>
                                </td>
                                <td>{{ p.criado_em }}</td>
                                <td>
                                    <select class="form-select form-select-sm" style="width: auto;" onchange="atribuirProcesso({{ p.id }}, this.value)">
                                        <option value="">Atribuir para...</option>
                                        {% for a in analistas %}
                                        <option value="{{ a.id }}">{{ a.primeiro_nome }}</option>
                                        {% endfor %}
                                    </select>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center py-4">
                    <i class="fas fa-check-circle fa-3x text-success mb-3"></i>
                    <h5>Todos os processos estão atribuídos!</h5>
                </div>
                {% endif %}
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    function novoProcesso() {
        const numero = prompt('Número do processo:');
        if (!numero) return;
        
        const titulo = prompt('Título do processo:');
        if (!titulo) return;
        
        const prioridade = prompt('Prioridade (baixa/media/alta/critica):', 'media');
        
        fetch('/api/processo/criar', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({numero, titulo, prioridade})
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Erro: ' + data.message);
            }
        });
    }

    function atribuirProcesso(processoId, analistaId) {
        if (!analistaId) return;
        
        fetch(`/api/processo/${processoId}/atribuir`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({analista_id: analistaId})
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('Erro: ' + data.message);
            }
        });
    }
    </script>
</body>
</html>
'''

PAINEL_ANALISTA_TEMPLATE = '''
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Painel do Analista</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .processo-card { 
            border-left: 4px solid #007bff; 
            transition: all 0.3s ease;
        }
        .processo-card:hover { 
            box-shadow: 0 4px 8px rgba(0,0,0,0.1); 
            transform: translateY(-2px);
        }
        .priority-critica { border-left-color: #dc3545; }
        .priority-alta { border-left-color: #fd7e14; }
        .priority-media { border-left-color: #ffc107; }
        .priority-baixa { border-left-color: #28a745; }
        .status-novo { background: #e3f2fd; color: #1976d2; }
        .status-em_analise { background: #fff3e0; color: #f57c00; }
        .status-aguardando { background: #fce4ec; color: #c2185b; }
        .status-concluido { background: #e8f5e8; color: #388e3c; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-user me-2"></i>Painel do Analista
            </a>
            <div class="navbar-nav ms-auto">
                <span class="navbar-text me-3">
                    <i class="fas fa-user me-1"></i>{{ current_user.primeiro_nome }}
                </span>
                <a class="btn btn-outline-light btn-sm" href="/logout">
                    <i class="fas fa-sign-out-alt me-1"></i>Sair
                </a>
            </div>
        </div>
    </nav>

    <div class="container py-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <h2 class="mb-4"><i class="fas fa-tasks me-2"></i>Meus Processos</h2>

        <!-- Estatísticas do Analista -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-primary">{{ stats.total }}</h3>
                        <p class="card-text">Total</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-info">{{ stats.novo }}</h3>
                        <p class="card-text">Novos</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-warning">{{ stats.em_analise }}</h3>
                        <p class="card-text">Em Análise</p>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-center">
                    <div class="card-body">
                        <h3 class="text-success">{{ stats.concluido }}</h3>
                        <p class="card-text">Concluídos</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Lista de Processos -->
        {% if processos %}
        <div class="row">
            {% for p in processos %}
            <div class="col-lg-6 mb-3">
                <div class="card processo-card priority-{{ p.prioridade }}">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <h6 class="card-title mb-0">{{ p.numero }}</h6>
                            <span class="badge status-{{ p.status }}">{{ p.status.replace('_', ' ') }}</span>
                        </div>
                        <h6 class="text-primary mb-2">{{ p.titulo }}</h6>
                        {% if p.descricao %}
                        <p class="card-text text-muted small">{{ p.descricao }}</p>
                        {% endif %}
                        
                        <div class="mb-3">
                            <label class="form-label small">Status:</label>
                            <select class="form-select form-select-sm" onchange="alterarStatus({{ p.id }}, this.value)">
                                <option value="novo" {% if p.status == 'novo' %}selected{% endif %}>Novo</option>
                                <option value="em_analise" {% if p.status == 'em_analise' %}selected{% endif %}>Em Análise</option>
                                <option value="aguardando" {% if p.status == 'aguardando' %}selected{% endif %}>Aguardando</option>
                                <option value="concluido" {% if p.status == 'concluido' %}selected{% endif %}>Concluído</option>
                            </select>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label small">Observações:</label>
                            <textarea class="form-control form-control-sm" rows="2" 
                                      onblur="salvarObservacoes({{ p.id }}, this.value)"
                                      placeholder="Suas observações...">{{ p.observacoes or '' }}</textarea>
                        </div>
                        
                        <div class="d-flex justify-content-between align-items-center">
                            <small class="text-muted">
                                <i class="fas fa-clock me-1"></i>{{ p.criado_em }}
                            </small>
                            <span class="badge bg-secondary">{{ p.prioridade }}</span>
                        </div>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="text-center py-5">
            <i class="fas fa-inbox fa-3x text-muted mb-3"></i>
            <h5>Nenhum processo atribuído</h5>
            <p class="text-muted">Aguarde a atribuição de processos.</p>
        </div>
        {% endif %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    function alterarStatus(processoId, novoStatus) {
        fetch(`/api/processo/${processoId}/atualizar`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({status: novoStatus})
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                // Atualizar badge visual
                const select = document.querySelector(`[onchange*="${processoId}"]`);
                const card = select.closest('.card');
                const badge = card.querySelector('.badge');
                badge.className = `badge status-${novoStatus}`;
                badge.textContent = novoStatus.replace('_', ' ');
                
                showToast('Status atualizado!', 'success');
            } else {
                alert('Erro: ' + data.message);
            }
        });
    }

    function salvarObservacoes(processoId, observacoes) {
        fetch(`/api/processo/${processoId}/atualizar`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({observacoes})
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showToast('Observações salvas!', 'info');
            }
        });
    }

    function showToast(message, type) {
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} position-fixed top-0 end-0 m-3`;
        toast.style.zIndex = '9999';
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }
    </script>
</body>
</html>
'''

# =============================================================================
# ROTAS PRINCIPAIS
# =============================================================================

@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    if user['papel'] in ('gerente', 'admin'):
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('painel_analista'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        primeiro_nome = request.form.get('primeiro_nome', '').strip()
        senha = request.form.get('senha', '')
        
        if not primeiro_nome or not senha:
            flash('Nome e senha são obrigatórios.', 'error')
            return render_template_string(LOGIN_TEMPLATE)
        
        conn = get_db()
        cursor = conn.execute(
            'SELECT id, senha_hash, papel FROM usuarios WHERE LOWER(primeiro_nome) = LOWER(?) AND ativo = 1',
            (primeiro_nome,)
        )
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], senha):
            session['user_id'] = user[0]
            session['user_papel'] = user[2]
            flash(f'Bem-vindo, {primeiro_nome}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciais inválidas.', 'error')
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
@role_required('gerente', 'admin')
def dashboard():
    conn = get_db()
    
    # Estatísticas
    cursor = conn.execute('SELECT COUNT(*) FROM processos')
    total = cursor.fetchone()[0]
    
    cursor = conn.execute("SELECT COUNT(*) FROM processos WHERE status != 'concluido'")
    pendentes = cursor.fetchone()[0]
    
    cursor = conn.execute("SELECT COUNT(*) FROM processos WHERE status = 'concluido'")
    concluidos = cursor.fetchone()[0]
    
    cursor = conn.execute('SELECT COUNT(*) FROM processos WHERE analista_id IS NULL')
    nao_atribuidos = cursor.fetchone()[0]
    
    # Processos não atribuídos
    cursor = conn.execute('''
        SELECT id, numero, titulo, prioridade, criado_em 
        FROM processos 
        WHERE analista_id IS NULL 
        ORDER BY criado_em DESC
    ''')
    processos_nao_atribuidos = [
        {
            'id': row[0], 'numero': row[1], 'titulo': row[2], 
            'prioridade': row[3], 'criado_em': row[4]
        }
        for row in cursor.fetchall()
    ]
    
    # Analistas
    cursor = conn.execute("SELECT id, primeiro_nome FROM usuarios WHERE papel = 'analista' AND ativo = 1")
    analistas = [{'id': row[0], 'primeiro_nome': row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    stats = {
        'total': total,
        'pendentes': pendentes,
        'concluidos': concluidos,
        'nao_atribuidos': nao_atribuidos
    }
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        current_user=get_current_user(),
        stats=stats,
        processos_nao_atribuidos=processos_nao_atribuidos,
        analistas=analistas
    )

@app.route('/analista')
@login_required
def painel_analista():
    user = get_current_user()
    conn = get_db()
    
    # Processos do analista
    cursor = conn.execute('''
        SELECT id, numero, titulo, descricao, status, prioridade, observacoes, criado_em
        FROM processos 
        WHERE analista_id = ? 
        ORDER BY criado_em DESC
    ''', (user['id'],))
    
    processos = [
        {
            'id': row[0], 'numero': row[1], 'titulo': row[2], 'descricao': row[3],
            'status': row[4], 'prioridade': row[5], 'observacoes': row[6], 'criado_em': row[7]
        }
        for row in cursor.fetchall()
    ]
    
    # Estatísticas
    stats = {
        'total': len(processos),
        'novo': len([p for p in processos if p['status'] == 'novo']),
        'em_analise': len([p for p in processos if p['status'] == 'em_analise']),
        'aguardando': len([p for p in processos if p['status'] == 'aguardando']),
        'concluido': len([p for p in processos if p['status'] == 'concluido'])
    }
    
    conn.close()
    
    return render_template_string(
        PAINEL_ANALISTA_TEMPLATE,
        current_user=user,
        processos=processos,
        stats=stats
    )

# =============================================================================
# API SIMPLES
# =============================================================================

@app.route('/api/processo/criar', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_criar_processo():
    try:
        data = request.get_json()
        numero = data.get('numero', '').strip()
        titulo = data.get('titulo', '').strip()
        prioridade = data.get('prioridade', 'media')
        
        if not numero or not titulo:
            return jsonify({'success': False, 'message': 'Número e título são obrigatórios'})
        
        user = get_current_user()
        conn = get_db()
        
        # Verificar se número já existe
        cursor = conn.execute('SELECT id FROM processos WHERE numero = ?', (numero,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Número do processo já existe'})
        
        # Criar processo
        conn.execute('''
            INSERT INTO processos (numero, titulo, prioridade, gerente_id)
            VALUES (?, ?, ?, ?)
        ''', (numero, titulo, prioridade, user['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Processo criado com sucesso'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/atribuir', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_atribuir_processo(processo_id):
    try:
        data = request.get_json()
        analista_id = data.get('analista_id')
        
        conn = get_db()
        conn.execute(
            'UPDATE processos SET analista_id = ?, atualizado_em = CURRENT_TIMESTAMP WHERE id = ?',
            (analista_id, processo_id)
        )
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Processo atribuído com sucesso'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/atualizar', methods=['POST'])
@login_required
def api_atualizar_processo(processo_id):
    try:
        data = request.get_json()
        user = get_current_user()
        
        conn = get_db()
        
        # Verificar permissões para analistas
        if user['papel'] == 'analista':
            cursor = conn.execute('SELECT analista_id FROM processos WHERE id = ?', (processo_id,))
            processo = cursor.fetchone()
            if not processo or processo[0] != user['id']:
                conn.close()
                return jsonify({'success': False, 'message': 'Sem permissão'})
        
        # Atualizar campos
        updates = []
        params = []
        
        if 'status' in data:
            updates.append('status = ?')
            params.append(data['status'])
            
            if data['status'] == 'concluido':
                updates.append('data_conclusao = CURRENT_TIMESTAMP')
        
        if 'observacoes' in data:
            updates.append('observacoes = ?')
            params.append(data['observacoes'])
        
        if updates:
            updates.append('atualizado_em = CURRENT_TIMESTAMP')
            params.append(processo_id)
            
            sql = f'UPDATE processos SET {", ".join(updates)} WHERE id = ?'
            conn.execute(sql, params)
            conn.commit()
        
        conn.close()
        
        return jsonify({'success': True, 'message': 'Processo atualizado'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

# =============================================================================
# INICIALIZAÇÃO
# =============================================================================

if __name__ == '__main__':
    print("🚀 Iniciando Sistema SAR...")
    
    # Inicializar banco
    init_db()
    print("✓ Banco de dados inicializado")
    
    # Criar usuários padrão
    criar_usuarios_padrao()
    print("✓ Usuários padrão criados")
    
    print("\n" + "="*50)
    print("📋 SISTEMA SAR FUNCIONANDO")
    print("="*50)
    print("🌐 Acesse: http://localhost:5000")
    print("\n👥 Usuários:")
    print("   • admin / admin123 (Admin)")
    print("   • Erica / 1234 (Gerente)")
    print("   • Bruno / 1234 (Analista)")
    print("   • Vanessa / 1234 (Analista)")
    print("   • Alessandro / 1234 (Analista)")
    print("   • Carmen / 1234 (Analista)")
    print("   • Zenilda / 1234 (Analista)")
    print("="*50)
    
    # Executar aplicação
    app.run(debug=True, host='0.0.0.0', port=5000)