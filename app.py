import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
import json

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# CONFIGURAÇÃO BÁSICA
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sar-secret-key-change-in-production'
app.config['DATABASE'] = 'sar.db'

# =============================================================================
# CONTEXTO GLOBAL PARA NAVEGAÇÃO INTEGRADA
# =============================================================================

@app.context_processor
def inject_navigation_context():
    """Injetar contexto de navegação em todos os templates"""
    user = get_current_user()
    if user:
        # Menu de navegação baseado no papel do usuário
        nav_items = []
        
        if user['papel'] in ('gerente', 'admin'):
            nav_items = [
                {'name': 'Painel Gerência', 'url': '/painel-gerencia', 'icon': 'fas fa-tachometer-alt'},
                {'name': 'Central Estatísticas', 'url': '/central-estatisticas', 'icon': 'fas fa-chart-line'},
                {'name': 'Meus Processos', 'url': '/painel-analista', 'icon': 'fas fa-tasks'},
            ]
        else:
            nav_items = [
                {'name': 'Meus Processos', 'url': '/painel-analista', 'icon': 'fas fa-tasks'},
            ]
        
        return {
            'current_user': user,
            'nav_items': nav_items,
            'is_admin': user['papel'] == 'admin',
            'is_gerente': user['papel'] in ('gerente', 'admin'),
            'is_analista': user['papel'] == 'analista'
        }
    
    return {'current_user': None, 'nav_items': [], 'is_admin': False, 'is_gerente': False, 'is_analista': False}

# =============================================================================
# MIGRAÇÃO E BANCO DE DADOS
# =============================================================================

def verificar_e_migrar_banco():
    """Verificar estrutura do banco e migrar se necessário"""
    conn = sqlite3.connect(app.config['DATABASE'])
    
    # Verificar estrutura atual
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    # Criar tabelas se não existirem
    if 'usuarios' not in tables:
        conn.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                primeiro_nome TEXT UNIQUE NOT NULL,
                senha_hash TEXT NOT NULL,
                papel TEXT NOT NULL DEFAULT 'analista',
                email TEXT,
                ativo BOOLEAN DEFAULT 1,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Tabela usuarios criada")
    else:
        # Verificar e adicionar colunas que podem estar faltando
        cursor = conn.execute("PRAGMA table_info(usuarios)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'email' not in columns:
            conn.execute('ALTER TABLE usuarios ADD COLUMN email TEXT')
            print("✓ Coluna email adicionada à tabela usuarios")
    
    if 'processos' not in tables:
        conn.execute('''
            CREATE TABLE processos (
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
                data_atribuicao TIMESTAMP,
                FOREIGN KEY (gerente_id) REFERENCES usuarios (id),
                FOREIGN KEY (analista_id) REFERENCES usuarios (id)
            )
        ''')
        print("✓ Tabela processos criada")
    else:
        # Verificar e adicionar colunas que podem estar faltando
        cursor = conn.execute("PRAGMA table_info(processos)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'data_atribuicao' not in columns:
            conn.execute('ALTER TABLE processos ADD COLUMN data_atribuicao TIMESTAMP')
            print("✓ Coluna data_atribuicao adicionada à tabela processos")
    
    conn.commit()
    conn.close()

def get_db():
    """Obter conexão com banco"""
    return sqlite3.connect(app.config['DATABASE'])

def criar_usuarios_padrao():
    """Criar usuários padrão"""
    usuarios = [
        ('admin', 'admin', 'admin123', 'admin@sar.local'),
        ('Erica', 'gerente', '1234', 'erica@sar.local'),
        ('Bruno', 'analista', '1234', 'bruno@sar.local'),
        ('Vanessa', 'analista', '1234', 'vanessa@sar.local'),
        ('Alessandro', 'analista', '1234', 'alessandro@sar.local'),
        ('Carmen', 'analista', '1234', 'carmen@sar.local'),
        ('Zenilda', 'analista', '1234', 'zenilda@sar.local'),
    ]
    
    conn = get_db()
    for nome, papel, senha, email in usuarios:
        # Verificar se já existe
        cursor = conn.execute('SELECT id FROM usuarios WHERE primeiro_nome = ?', (nome,))
        if not cursor.fetchone():
            senha_hash = generate_password_hash(senha)
            conn.execute(
                'INSERT INTO usuarios (primeiro_nome, papel, senha_hash, email) VALUES (?, ?, ?, ?)',
                (nome, papel, senha_hash, email)
            )
            print(f"✓ Usuário criado: {nome} ({papel})")
        else:
            # Atualizar senha
            senha_hash = generate_password_hash(senha)
            conn.execute(
                'UPDATE usuarios SET senha_hash = ?, papel = ?, email = ? WHERE primeiro_nome = ?',
                (senha_hash, papel, email, nome)
            )
            print(f"✓ Usuário atualizado: {nome}")
    
    conn.commit()
    conn.close()

# =============================================================================
# HELPER FUNCTIONS PARA VERIFICAR COLUNAS
# =============================================================================

def tem_coluna(tabela, coluna):
    """Verificar se uma coluna existe em uma tabela"""
    conn = get_db()
    cursor = conn.execute(f"PRAGMA table_info({tabela})")
    columns = [col[1] for col in cursor.fetchall()]
    conn.close()
    return coluna in columns

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
    
    if tem_coluna('usuarios', 'email'):
        cursor = conn.execute(
            'SELECT id, primeiro_nome, papel, email FROM usuarios WHERE id = ?', 
            (session['user_id'],)
        )
        user = cursor.fetchone()
        if user:
            return {
                'id': user[0],
                'primeiro_nome': user[1],
                'papel': user[2],
                'email': user[3]
            }
    else:
        cursor = conn.execute(
            'SELECT id, primeiro_nome, papel FROM usuarios WHERE id = ?', 
            (session['user_id'],)
        )
        user = cursor.fetchone()
        if user:
            return {
                'id': user[0],
                'primeiro_nome': user[1],
                'papel': user[2],
                'email': None
            }
    
    conn.close()
    return None

# =============================================================================
# ROTAS PRINCIPAIS
# =============================================================================

@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    if user['papel'] in ('gerente', 'admin'):
        return redirect(url_for('painel_gerencia'))
    else:
        return redirect(url_for('painel_analista'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        primeiro_nome = request.form.get('primeiro_nome', '').strip()
        senha = request.form.get('senha', '')
        
        if not primeiro_nome or not senha:
            flash('Nome e senha são obrigatórios.', 'error')
            return render_template('login.html')
        
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
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout realizado com sucesso.', 'success')
    return redirect(url_for('login'))

# =============================================================================
# PAINEL DE GERÊNCIA
# =============================================================================

@app.route('/painel-gerencia')
@login_required
@role_required('gerente', 'admin')
def painel_gerencia():
    """Painel de gerência com drag & drop e distribuição inteligente"""
    conn = get_db()
    
    # Analistas ativos
    if tem_coluna('usuarios', 'email'):
        cursor = conn.execute(
            "SELECT id, primeiro_nome, email FROM usuarios WHERE papel = 'analista' AND ativo = 1 ORDER BY primeiro_nome"
        )
        analistas = [
            {'id': row[0], 'primeiro_nome': row[1], 'email': row[2]}
            for row in cursor.fetchall()
        ]
    else:
        cursor = conn.execute(
            "SELECT id, primeiro_nome FROM usuarios WHERE papel = 'analista' AND ativo = 1 ORDER BY primeiro_nome"
        )
        analistas = [
            {'id': row[0], 'primeiro_nome': row[1], 'email': None}
            for row in cursor.fetchall()
        ]
    
    # Processos não atribuídos
    cursor = conn.execute('''
        SELECT id, numero, titulo, descricao, prioridade, status, criado_em 
        FROM processos 
        WHERE analista_id IS NULL AND status != 'cancelado'
        ORDER BY 
            CASE prioridade 
                WHEN 'critica' THEN 1 
                WHEN 'alta' THEN 2 
                WHEN 'media' THEN 3 
                WHEN 'baixa' THEN 4 
            END,
            criado_em DESC
    ''')
    processos_nao_atribuidos = [
        {
            'id': row[0], 'numero': row[1], 'titulo': row[2], 'descricao': row[3],
            'prioridade': row[4], 'status': row[5], 'criado_em': row[6]
        }
        for row in cursor.fetchall()
    ]
    
    # Carga de trabalho por analista
    carga_trabalho = {}
    for analista in analistas:
        cursor = conn.execute('''
            SELECT COUNT(*) FROM processos 
            WHERE analista_id = ? AND status IN ('novo', 'em_analise', 'aguardando')
        ''', (analista['id'],))
        carga_trabalho[analista['id']] = cursor.fetchone()[0]
    
    # Processos recentemente atribuídos - VERSÃO COMPATÍVEL
    processos_recentes = []
    if tem_coluna('processos', 'data_atribuicao'):
        # Usar data_atribuicao se existir
        data_limite = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor = conn.execute('''
            SELECT p.id, p.numero, p.titulo, p.prioridade, p.data_atribuicao, u.primeiro_nome
            FROM processos p
            LEFT JOIN usuarios u ON p.analista_id = u.id
            WHERE p.data_atribuicao IS NOT NULL AND p.data_atribuicao >= ?
            ORDER BY p.data_atribuicao DESC
            LIMIT 10
        ''', (data_limite,))
        
        for row in cursor.fetchall():
            processos_recentes.append({
                'id': row[0], 
                'numero': row[1], 
                'titulo': row[2], 
                'prioridade': row[3],
                'data_atribuicao': datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S') if row[4] else None,
                'analista': {'primeiro_nome': row[5]} if row[5] else None
            })
    else:
        # Fallback: usar atualizado_em
        data_limite = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        cursor = conn.execute('''
            SELECT p.id, p.numero, p.titulo, p.prioridade, p.atualizado_em, u.primeiro_nome
            FROM processos p
            LEFT JOIN usuarios u ON p.analista_id = u.id
            WHERE p.analista_id IS NOT NULL AND p.atualizado_em >= ?
            ORDER BY p.atualizado_em DESC
            LIMIT 10
        ''', (data_limite,))
        
        for row in cursor.fetchall():
            processos_recentes.append({
                'id': row[0], 
                'numero': row[1], 
                'titulo': row[2], 
                'prioridade': row[3],
                'data_atribuicao': datetime.strptime(row[4], '%Y-%m-%d %H:%M:%S') if row[4] else None,
                'analista': {'primeiro_nome': row[5]} if row[5] else None
            })
    
    conn.close()
    
    return render_template('painel_gerencia.html',
                         analistas=analistas,
                         processos_nao_atribuidos=processos_nao_atribuidos,
                         carga_trabalho=carga_trabalho,
                         processos_recentes=processos_recentes)

# =============================================================================
# PAINEL DO ANALISTA
# =============================================================================

@app.route('/painel-analista')
@login_required
def painel_analista():
    """Painel individual do analista"""
    user = get_current_user()
    conn = get_db()
    
    # Processos do analista
    cursor = conn.execute('''
        SELECT id, numero, titulo, descricao, status, prioridade, observacoes, criado_em
        FROM processos 
        WHERE analista_id = ? 
        ORDER BY 
            CASE status 
                WHEN 'novo' THEN 1 
                WHEN 'em_analise' THEN 2 
                WHEN 'aguardando' THEN 3 
                WHEN 'concluido' THEN 4 
            END,
            CASE prioridade 
                WHEN 'critica' THEN 1 
                WHEN 'alta' THEN 2 
                WHEN 'media' THEN 3 
                WHEN 'baixa' THEN 4 
            END,
            criado_em DESC
    ''', (user['id'],))
    
    processos = [
        {
            'id': row[0], 'numero': row[1], 'titulo': row[2], 'descricao': row[3],
            'status': row[4], 'prioridade': row[5], 'observacoes': row[6], 'criado_em': row[7]
        }
        for row in cursor.fetchall()
    ]
    
    # Estatísticas do analista
    stats = {
        'total': len(processos),
        'novo': len([p for p in processos if p['status'] == 'novo']),
        'em_analise': len([p for p in processos if p['status'] == 'em_analise']),
        'aguardando': len([p for p in processos if p['status'] == 'aguardando']),
        'concluido': len([p for p in processos if p['status'] == 'concluido'])
    }
    
    conn.close()
    
    return render_template('painel_analista.html',
                         processos=processos,
                         stats=stats)

# =============================================================================
# CENTRAL DE ESTATÍSTICAS
# =============================================================================

@app.route('/central-estatisticas')
@login_required
@role_required('gerente', 'admin')
def central_estatisticas():
    """Central de estatísticas avançada com gráficos em tempo real"""
    return render_template('central_estatisticas.html')

# =============================================================================
# DASHBOARD (COMPATIBILIDADE)
# =============================================================================

@app.route('/dashboard')
@login_required
@role_required('gerente', 'admin')
def dashboard():
    """Dashboard simplificado - redireciona para painel gerência"""
    return redirect(url_for('painel_gerencia'))

# =============================================================================
# APIs (mantidas as mesmas)
# =============================================================================

@app.route('/api/processo/criar', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_criar_processo():
    try:
        data = request.get_json()
        numero = data.get('numero', '').strip()
        titulo = data.get('titulo', '').strip()
        descricao = data.get('descricao', '').strip()
        prioridade = data.get('prioridade', 'media')
        analista_nome = data.get('analista_nome', '').strip()
        
        if not numero or not titulo:
            return jsonify({'success': False, 'message': 'Número e título são obrigatórios'})
        
        user = get_current_user()
        conn = get_db()
        
        # Verificar se número já existe
        cursor = conn.execute('SELECT id FROM processos WHERE numero = ?', (numero,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Número do processo já existe'})
        
        # Buscar analista se especificado
        analista_id = None
        if analista_nome:
            cursor = conn.execute(
                'SELECT id FROM usuarios WHERE LOWER(primeiro_nome) = LOWER(?) AND papel = "analista" AND ativo = 1',
                (analista_nome,)
            )
            analista = cursor.fetchone()
            if analista:
                analista_id = analista[0]
        
        # Criar processo
        if tem_coluna('processos', 'data_atribuicao') and analista_id:
            data_atribuicao = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor = conn.execute('''
                INSERT INTO processos (numero, titulo, descricao, prioridade, gerente_id, analista_id, data_atribuicao)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (numero, titulo, descricao, prioridade, user['id'], analista_id, data_atribuicao))
        else:
            cursor = conn.execute('''
                INSERT INTO processos (numero, titulo, descricao, prioridade, gerente_id, analista_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (numero, titulo, descricao, prioridade, user['id'], analista_id))
        
        processo_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Retornar dados do processo criado
        processo = {
            'id': processo_id,
            'numero': numero,
            'titulo': titulo,
            'descricao': descricao,
            'prioridade': prioridade,
            'status': 'novo',
            'analista_id': analista_id
        }
        
        return jsonify({'success': True, 'message': 'Processo criado com sucesso', 'processo': processo})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/atribuir', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_atribuir_processo(processo_id):
    try:
        data = request.get_json()
        analista_nome = data.get('analista_nome', '').strip()
        analista_id = data.get('analista_id')
        
        if not analista_nome and not analista_id:
            return jsonify({'success': False, 'message': 'Nome ou ID do analista é obrigatório'})
        
        conn = get_db()
        
        # Buscar analista por nome se necessário
        if analista_nome and not analista_id:
            cursor = conn.execute(
                'SELECT id FROM usuarios WHERE LOWER(primeiro_nome) = LOWER(?) AND papel = "analista" AND ativo = 1',
                (analista_nome,)
            )
            analista = cursor.fetchone()
            if not analista:
                conn.close()
                return jsonify({'success': False, 'message': f'Analista {analista_nome} não encontrado'})
            analista_id = analista[0]
        
        # Atribuir processo
        if tem_coluna('processos', 'data_atribuicao'):
            data_atribuicao = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('''
                UPDATE processos 
                SET analista_id = ?, data_atribuicao = ?, atualizado_em = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (analista_id, data_atribuicao, processo_id))
        else:
            conn.execute('''
                UPDATE processos 
                SET analista_id = ?, atualizado_em = CURRENT_TIMESTAMP 
                WHERE id = ?
            ''', (analista_id, processo_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'Processo atribuído para {analista_nome or analista_id}'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/atualizar', methods=['POST', 'PUT'])
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
                return jsonify({'success': False, 'message': 'Sem permissão para alterar este processo'})
        
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
        
        if 'prioridade' in data and user['papel'] in ('gerente', 'admin'):
            updates.append('prioridade = ?')
            params.append(data['prioridade'])
        
        if updates:
            updates.append('atualizado_em = CURRENT_TIMESTAMP')
            params.append(processo_id)
            
            sql = f'UPDATE processos SET {", ".join(updates)} WHERE id = ?'
            conn.execute(sql, params)
            conn.commit()
        
        conn.close()
        
        return jsonify({'success': True, 'message': 'Processo atualizado com sucesso'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

# =============================================================================
# ESTATÍSTICAS API
# =============================================================================

@app.route('/sar/api/estatisticas-tempo-real')
@login_required
def api_estatisticas_tempo_real():
    """API para estatísticas em tempo real"""
    try:
        conn = get_db()
        
        # Estatísticas gerais
        cursor = conn.execute('SELECT COUNT(*) FROM processos')
        total_processos = cursor.fetchone()[0]
        
        cursor = conn.execute('SELECT COUNT(*) FROM processos WHERE status = "concluido"')
        concluidos = cursor.fetchone()[0]
        
        cursor = conn.execute('SELECT COUNT(*) FROM processos WHERE analista_id IS NULL')
        nao_atribuidos = cursor.fetchone()[0]
        
        # Estatísticas do dia
        hoje = datetime.now().strftime('%Y-%m-%d')
        cursor = conn.execute('SELECT COUNT(*) FROM processos WHERE DATE(criado_em) = ?', (hoje,))
        criados_hoje = cursor.fetchone()[0]
        
        cursor = conn.execute('SELECT COUNT(*) FROM processos WHERE DATE(data_conclusao) = ?', (hoje,))
        concluidos_hoje = cursor.fetchone()[0]
        
        # Produtividade semanal
        semana_passada = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        cursor = conn.execute(
            'SELECT COUNT(*) FROM processos WHERE data_conclusao >= ? AND data_conclusao IS NOT NULL',
            (semana_passada,)
        )
        concluidos_semana = cursor.fetchone()[0]
        
        # Tempo médio de resolução (em dias)
        cursor = conn.execute('''
            SELECT AVG(
                CAST((JULIANDAY(data_conclusao) - JULIANDAY(criado_em)) AS INTEGER)
            ) 
            FROM processos 
            WHERE data_conclusao IS NOT NULL
        ''')
        tempo_medio = cursor.fetchone()[0] or 0
        
        conn.close()
        
        estatisticas = {
            'metricas_dia': {
                'total_processos': total_processos,
                'concluidos_total': concluidos,
                'nao_atribuidos': nao_atribuidos,
                'criados_hoje': criados_hoje,
                'concluidos_hoje': concluidos_hoje,
                'tempo_medio_dias': round(tempo_medio, 1)
            },
            'metas': {
                'progresso_diario': min(100, (concluidos_hoje / max(1, criados_hoje)) * 100),
                'progresso_semanal': min(100, (concluidos_semana / 25) * 100),
            },
            'produtividade_semanal': {
                'concluidos_semana': concluidos_semana,
                'meta_semanal': 25
            }
        }
        
        return jsonify({'success': True, 'estatisticas': estatisticas})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

# =============================================================================
# CRIAR TEMPLATES COM NAVEGAÇÃO INTEGRADA
# =============================================================================

def criar_templates_necessarios():
    """Criar templates necessários se não existirem"""
    
    # Criar diretório templates se não existir
    os.makedirs('templates', exist_ok=True)
    
    # Criar login.html se não existir
    login_path = os.path.join('templates', 'login.html')
    if not os.path.exists(login_path):
        login_content = '''<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAR - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        .login-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 20px 20px 0 0;
            padding: 2rem 1.5rem;
            text-align: center;
        }
        .btn-login {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 10px;
            padding: 0.75rem 2rem;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-lg-5 col-md-7 col-sm-9">
                <div class="login-card">
                    <div class="login-header">
                        <div style="font-size: 3rem; margin-bottom: 1rem;">
                            <i class="fas fa-building"></i>
                        </div>
                        <h2 class="mb-2">Sistema SAR</h2>
                        <p class="mb-0 opacity-75">Setor de Arrecadação</p>
                    </div>
                    
                    <div class="p-4">
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
                        
                        <form method="POST">
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" id="primeiro_nome" name="primeiro_nome" placeholder="Primeiro Nome" required autofocus>
                                <label for="primeiro_nome"><i class="fas fa-user me-2"></i>Primeiro Nome</label>
                            </div>
                            
                            <div class="form-floating mb-4">
                                <input type="password" class="form-control" id="senha" name="senha" placeholder="Senha" required>
                                <label for="senha"><i class="fas fa-lock me-2"></i>Senha</label>
                            </div>
                            
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-login">
                                    <i class="fas fa-sign-in-alt me-2"></i>Entrar no Sistema
                                </button>
                            </div>
                        </form>
                        
                        <div class="text-center mt-4">
                            <small class="text-muted">
                                <strong>Usuários para teste:</strong><br>
                                Erica/1234 (Gerente) | Bruno/1234 (Analista) | admin/admin123
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>'''
        
        with open(login_path, 'w', encoding='utf-8') as f:
            f.write(login_content)
        
        print("✓ Template login.html criado")

# =============================================================================
# INICIALIZAÇÃO
# =============================================================================

if __name__ == '__main__':
    print("🚀 Iniciando Sistema SAR - COM NAVEGAÇÃO INTEGRADA...")
    
    # Criar templates necessários
    criar_templates_necessarios()
    print("✓ Templates necessários verificados")
    
    # Verificar e migrar banco
    verificar_e_migrar_banco()
    print("✓ Banco de dados verificado e migrado")
    
    # Criar usuários padrão
    criar_usuarios_padrao()
    print("✓ Usuários padrão verificados")
    
    print("\n" + "="*60)
    print("📋 SISTEMA SAR - NAVEGAÇÃO INTEGRADA ATIVA")
    print("="*60)
    print("🌐 Acesse: http://localhost:5000")
    print("\n🎯 Funcionalidades Disponíveis:")
    print("   • LOGIN: http://localhost:5000/login")
    print("   • PAINEL GERÊNCIA: http://localhost:5000/painel-gerencia")
    print("   • PAINEL ANALISTA: http://localhost:5000/painel-analista")
    print("   • CENTRAL ESTATÍSTICAS: http://localhost:5000/central-estatisticas")
    print("   • LOGOUT: http://localhost:5000/logout")
    print("\n👥 Usuários:")
    print("   • admin / admin123 (Admin)")
    print("   • Erica / 1234 (Gerente)")
    print("   • Bruno / 1234 (Analista)")
    print("   • Vanessa / 1234 (Analista)")
    print("   • Alessandro / 1234 (Analista)")
    print("   • Carmen / 1234 (Analista)")
    print("   • Zenilda / 1234 (Analista)")
    print("\n✨ NOVIDADES:")
    print("   • Navegação integrada entre todos os ambientes")
    print("   • Botão de logout visível em todas as páginas")
    print("   • Menu de navegação baseado no papel do usuário")
    print("   • Transição fácil entre painéis")
    print("="*60)
    
    # Executar aplicação
    app.run(debug=True, host='0.0.0.0', port=5000)