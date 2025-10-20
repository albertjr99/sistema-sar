import os
import sqlite3
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_from_directory
import json
import csv
import io
import shutil

# --------------------------------------------------------------------
# Dependências opcionais (graceful fallback)
# --------------------------------------------------------------------
try:
    import openpyxl
except Exception:
    openpyxl = None

try:
    import pdfplumber
except Exception:
    pdfplumber = None

# =============================================================================
# CONFIGURAÇÃO BÁSICA
# =============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sar-secret-key-change-in-production'
app.config['DATABASE'] = 'sar.db'

# =============================================================================
# FUNÇÕES DE ACESSO / DECORATORS (ANTES DAS ROTAS)
# =============================================================================

def get_db():
    """Obter conexão com banco"""
    return sqlite3.connect(app.config['DATABASE'])

def login_required(f):
    """Decorator simples baseado em sessão."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """
    Restringe acesso por papel.
    Uso: @role_required('gerente', 'admin')
    """
    def decorator(f):
        @wraps(f)  # preserva o __name__ da view original
        def decorated_function(*args, **kwargs):
            # Exige login
            if 'user_id' not in session:
                return redirect(url_for('login'))

            # Lê o papel do usuário logado
            conn = get_db()
            try:
                row = conn.execute(
                    'SELECT papel FROM usuarios WHERE id = ?',
                    (session['user_id'],)
                ).fetchone()
            finally:
                conn.close()

            papel = row[0] if row else None
            if papel not in roles:
                # Para APIs, retorna JSON 403; para páginas, redireciona
                if request.path.startswith('/api/') or request.is_json:
                    return jsonify({'success': False, 'message': 'Permissão negada'}), 403
                flash('Permissão negada.', 'error')
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def get_current_user():
    """Obter usuário atual (dict) a partir da sessão."""
    if 'user_id' not in session:
        return None
    conn = get_db()
    try:
        cursor = conn.execute(
            'SELECT id, primeiro_nome, papel FROM usuarios WHERE id = ?', 
            (session['user_id'],)
        )
        row = cursor.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {'id': row[0], 'primeiro_nome': row[1], 'papel': row[2]}

# =============================================================================
# CONTEXTO GLOBAL PARA NAVEGAÇÃO INTEGRADA
# =============================================================================
# =============================================================================
# PRODUTIVIDADE (fonte única para tabela e PDF)
# =============================================================================

def _periodo_where_for_historico(periodo, inicio=None, fim=None):
    """
    Gera cláusula WHERE para filtro de período.
    Suporta: hoje, semana, mes, trimestre, ano (default), historico, intervalo/personalizado.
    """
    where = []
    params = []

    if periodo == 'hoje':
        where.append("date(data_distribuicao) = date('now')")
    elif periodo == 'semana':
        where.append("date(data_distribuicao) >= date('now','-7 days')")
    elif periodo == 'mes':
        where.append("date(data_distribuicao) >= date('now','-1 month')")
    elif periodo == 'trimestre':
        where.append("date(data_distribuicao) >= date('now','-3 months')")
    elif periodo in ('intervalo', 'personalizado') and inicio and fim:
        where.append("date(data_distribuicao) BETWEEN date(?) AND date(?)")
        params += [inicio, fim]
    elif periodo == 'historico':
        # Sem filtro (todo o histórico)
        pass
    else:
        # ano (default)
        where.append("strftime('%Y', data_distribuicao) = strftime('%Y','now')")

    return " AND ".join(where) if where else "1=1", params

def _dias_do_periodo(periodo, inicio=None, fim=None):
    """
    Estima quantidade de dias no período para médias.
    Para 'historico' usa fallback simplificado (365) para evitar consultas extras.
    """
    hoje = date.today()
    if periodo == 'hoje':
        return 1
    if periodo == 'semana':
        return 7
    if periodo == 'mes':
        return 30
    if periodo == 'trimestre':
        return 90
    if periodo in ('intervalo', 'personalizado') and inicio and fim:
        try:
            di = datetime.strptime(inicio, "%Y-%m-%d").date()
            df = datetime.strptime(fim, "%Y-%m-%d").date()
            return max((df - di).days + 1, 1)
        except Exception:
            return 1
    if periodo == 'historico':
        return 365  # simplificado
    # ano
    di = date(hoje.year, 1, 1)
    return (hoje - di).days + 1


@app.route('/sar/api/produtividade', endpoint='sar_api_produtividade')
@login_required
def api_produtividade():
    """
    Fonte única para a tabela detalhada e o PDF.
    Base: historico_setor (chave da sua planilha).
    Parâmetros:
      - periodo: hoje|semana|mes|ano (default)|intervalo
      - inicio, fim (YYYY-MM-DD) quando periodo=intervalo
    """
    periodo = request.args.get('periodo', 'ano')
    inicio = request.args.get('inicio') or None
    fim = request.args.get('fim') or None

    where, params = _periodo_where_for_historico(periodo, inicio, fim)
    dias_periodo = _dias_do_periodo(periodo, inicio, fim)

    conn = get_db()

    # Excluir gerente 'Erica' das estatísticas
    where_filtrado = f"{where} AND LOWER(COALESCE(analista,'')) <> 'erica'"

    # Total e concluídos por analista (usando data_conclusao preenchida)
    sql = f"""
        SELECT
            COALESCE(analista,'(Sem Analista)') AS analista,
            COUNT(*) AS total,
            SUM(CASE WHEN data_conclusao IS NOT NULL AND TRIM(data_conclusao) <> '' THEN 1 ELSE 0 END) AS concluidos
        FROM historico_setor
        WHERE {where_filtrado}
        GROUP BY analista
        ORDER BY total DESC, analista
    """
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    def classificar(per):
        # mesmas faixas do seu layout
        if per >= 97.0:
            return "Excelente"
        if per >= 95.0:
            return "Acima da Média"
        return "Abaixo da Média"

    saida = []
    total_total = total_conc = total_and = 0
    for r in rows:
        analista = r[0]
        total = int(r[1] or 0)
        concluidos = int(r[2] or 0)
        em_andamento = total - concluidos
        perc = round((concluidos / total * 100.0), 1) if total else 0.0
        media_dia = round(total / dias_periodo, 1) if dias_periodo else 0.0

        total_total += total
        total_conc += concluidos
        total_and += em_andamento

        saida.append({
            "analista": analista,
            "total": total,
            "concluidos": concluidos,
            "em_andamento": em_andamento,
            "percentual": perc,
            "media_diaria": media_dia,
            "performance": classificar(perc)
        })

    return jsonify({
        "success": True,
        "periodo": periodo,
        "dias_periodo": dias_periodo,
        "rows": saida,
        "labels": [r["analista"] for r in saida],
        "dataset_total": [r["total"] for r in saida],
        "dataset_concluidos": [r["concluidos"] for r in saida],
        "dataset_andamento": [r["em_andamento"] for r in saida],
        "totais": {
            "total": total_total,
            "concluidos": total_conc,
            "em_andamento": total_and,
            "percentual": round((total_conc / total_total * 100.0), 1) if total_total else 0.0
        }
    })

@app.context_processor
def inject_navigation_context():
    """Injetar contexto de navegação em todos os templates."""
    user = get_current_user()
    if user:
        if user['papel'] in ('gerente', 'admin'):
            nav_items = [
                {'name': 'Painel Gerência', 'url': '/painel-gerencia', 'icon': 'fas fa-tachometer-alt'},
                {'name': 'Central Estatísticas', 'url': '/central-estatisticas', 'icon': 'fas fa-chart-line'},
            ]
        else:
            nav_items = [
                {'name': 'Meus Processos', 'url': '/painel-analista', 'icon': 'fas fa-tasks'},
                {'name': 'Visão Geral', 'url': '/painel-gerencia', 'icon': 'fas fa-eye', 'tooltip': 'Visualização geral (apenas leitura)'},
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
    """Verificar estrutura do banco e migrar se necessário."""
    # Verificar se o arquivo de banco existe e é válido
    db_path = app.config['DATABASE']
    if os.path.exists(db_path):
        try:
            # Tentar conectar e fazer uma consulta simples para verificar se é um banco válido
            test_conn = sqlite3.connect(db_path, timeout=1.0)
            test_conn.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").fetchall()
            test_conn.close()
        except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
            print(f"⚠ Banco de dados corrompido detectado: {db_path}")
            print(f"⚠ Erro: {e}")
            print("🔧 Tentando remover banco corrompido...")
            try:
                # Fechar todas as conexões possíveis
                import gc
                gc.collect()
                
                # Tentar remover o arquivo
                os.remove(db_path)
                print("✓ Arquivo corrompido removido")
            except PermissionError:
                print("⚠ Arquivo em uso por outro processo!")
                print("💡 Solução: Feche todas as instâncias do sistema e execute:")
                print(f"💡 del {db_path}")
                print("💡 Depois execute o sistema novamente.")
                raise SystemExit("Sistema interrompido - remova o arquivo manualmente")
            except Exception as e:
                print(f"⚠ Erro ao remover arquivo: {e}")
                print("💡 Remova manualmente o arquivo sar.db e execute novamente")
                raise SystemExit("Sistema interrompido - erro ao remover banco corrompido")
    
    conn = sqlite3.connect(app.config['DATABASE'])

    # tabelas existentes
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    # usuarios (sem email)
    if 'usuarios' not in tables:
        conn.execute('''
            CREATE TABLE usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                primeiro_nome TEXT UNIQUE NOT NULL,
                senha_hash TEXT NOT NULL,
                papel TEXT NOT NULL DEFAULT 'analista',
                ativo BOOLEAN DEFAULT 1,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Tabela usuarios criada (sem email)")
    else:
        cursor = conn.execute("PRAGMA table_info(usuarios)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'email' in columns:
            conn.execute('''
                CREATE TABLE usuarios_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    primeiro_nome TEXT UNIQUE NOT NULL,
                    senha_hash TEXT NOT NULL,
                    papel TEXT NOT NULL DEFAULT 'analista',
                    ativo BOOLEAN DEFAULT 1,
                    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                INSERT INTO usuarios_new (id, primeiro_nome, senha_hash, papel, ativo, criado_em)
                SELECT id, primeiro_nome, senha_hash, papel, ativo, criado_em FROM usuarios
            ''')
            conn.execute('DROP TABLE usuarios')
            conn.execute('ALTER TABLE usuarios_new RENAME TO usuarios')
            print("✓ Email removido da tabela usuarios")

    # processos
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
        cursor = conn.execute("PRAGMA table_info(processos)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'data_atribuicao' not in columns:
            conn.execute('ALTER TABLE processos ADD COLUMN data_atribuicao TIMESTAMP')
            print("✓ Coluna data_atribuicao adicionada à tabela processos")
        
        # Adicionar colunas de contexto do processo
        if 'assunto' not in columns:
            conn.execute('ALTER TABLE processos ADD COLUMN assunto TEXT')
            print("✓ Coluna assunto adicionada à tabela processos")
        if 'setor_origem' not in columns:
            conn.execute('ALTER TABLE processos ADD COLUMN setor_origem TEXT')
            print("✓ Coluna setor_origem adicionada à tabela processos")
        if 'tipo_processo' not in columns:
            conn.execute('ALTER TABLE processos ADD COLUMN tipo_processo TEXT')
            print("✓ Coluna tipo_processo adicionada à tabela processos")

    # historico_setor
    if 'historico_setor' not in tables:
        conn.execute('''
            CREATE TABLE historico_setor (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ordem INTEGER,
                analista TEXT,
                numero TEXT,
                data_distribuicao DATE,
                data_conclusao DATE,
                interessado TEXT,
                assunto TEXT,
                setor_origem TEXT,
                tipo_processo TEXT,
                status_processo TEXT,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Tabela historico_setor criada")
    else:
        # Verificar se precisa migrar colunas
        cursor = conn.execute("PRAGMA table_info(historico_setor)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'setor_destino' in columns and 'tipo_processo' not in columns:
            # Migrar setor_destino para tipo_processo
            conn.execute('ALTER TABLE historico_setor ADD COLUMN tipo_processo TEXT')
            conn.execute('UPDATE historico_setor SET tipo_processo = setor_destino')
            print("✓ Coluna setor_destino migrada para tipo_processo")
        
        if 'tipo_processo' not in columns:
            conn.execute('ALTER TABLE historico_setor ADD COLUMN tipo_processo TEXT')
            print("✓ Coluna tipo_processo adicionada")
        
        if 'status_processo' not in columns:
            conn.execute('ALTER TABLE historico_setor ADD COLUMN status_processo TEXT')
            print("✓ Coluna status_processo adicionada")

    # sistema_meta
    if 'sistema_meta' not in tables:
        conn.execute('''
            CREATE TABLE sistema_meta (
                chave TEXT PRIMARY KEY,
                valor TEXT,
                atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Tabela sistema_meta criada")

    # notificacoes
    if 'notificacoes' not in tables:
        conn.execute('''
            CREATE TABLE notificacoes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_destino_id INTEGER NOT NULL,
                usuario_origem_id INTEGER NOT NULL,
                tipo TEXT NOT NULL DEFAULT 'status_change',
                titulo TEXT NOT NULL,
                mensagem TEXT NOT NULL,
                processo_numero TEXT,
                status_anterior TEXT,
                status_novo TEXT,
                lida BOOLEAN DEFAULT 0,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (usuario_destino_id) REFERENCES usuarios (id),
                FOREIGN KEY (usuario_origem_id) REFERENCES usuarios (id)
            )
        ''')
        print("✓ Tabela notificacoes criada")

    # chat_mensagens
    if 'chat_mensagens' not in tables:
        conn.execute('''
            CREATE TABLE chat_mensagens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                remetente_id INTEGER NOT NULL,
                destinatario_id INTEGER,
                tipo TEXT NOT NULL DEFAULT 'direto',
                assunto TEXT,
                mensagem TEXT NOT NULL,
                processo_numero TEXT,
                lida BOOLEAN DEFAULT 0,
                criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (remetente_id) REFERENCES usuarios (id),
                FOREIGN KEY (destinatario_id) REFERENCES usuarios (id)
            )
        ''')
        print("✓ Tabela chat_mensagens criada")

    conn.commit()
    conn.close()

def criar_usuarios_padrao():
    """Criar/atualizar usuários padrão."""
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
    try:
        # Primeiro, padronizar nomes existentes no histórico
        padronizar_nomes_historico(conn)

        for nome, papel, senha in usuarios:
            # Buscar hash e papel existentes para evitar rehash desnecessário
            cur = conn.execute('SELECT id, senha_hash, papel FROM usuarios WHERE primeiro_nome = ?', (nome,))
            row = cur.fetchone()

            if not row:
                # Forçar método rápido/compatível e sal seguro
                senha_hash = generate_password_hash(senha, method='pbkdf2:sha256', salt_length=16)
                conn.execute(
                    'INSERT INTO usuarios (primeiro_nome, papel, senha_hash) VALUES (?, ?, ?)',
                    (nome, papel, senha_hash)
                )
                print(f"✓ Usuário criado: {nome} ({papel})")
            else:
                user_id, existing_hash, existing_papel = row
                # Atualizar somente quando necessário
                precisa_atualizar_papel = existing_papel != papel
                precisa_atualizar_senha = not check_password_hash(existing_hash, senha)

                if precisa_atualizar_papel or precisa_atualizar_senha:
                    if precisa_atualizar_senha:
                        novo_hash = generate_password_hash(senha, method='pbkdf2:sha256', salt_length=16)
                    else:
                        novo_hash = existing_hash
                    conn.execute(
                        'UPDATE usuarios SET senha_hash = ?, papel = ? WHERE id = ?',
                        (novo_hash, papel, user_id)
                    )
                    print(f"✓ Usuário atualizado: {nome}")
                else:
                    # Nada a fazer
                    pass

        conn.commit()
    finally:
        conn.close()

def padronizar_nomes_historico(conn):
    """Padronizar nomes de analistas no histórico."""
    try:
        # Mapeamento de nomes para padronização
        mapeamento_nomes = {
            'BRUNO': 'Bruno',
            'bruno': 'Bruno',
            'ERICA': 'Erica',
            'erica': 'Erica',
            'VANESSA': 'Vanessa',
            'vanessa': 'Vanessa',
            'ALESSANDRO': 'Alessandro',
            'alessandro': 'Alessandro',
            'CARMEN': 'Carmen',
            'carmen': 'Carmen',
            'ZENILDA': 'Zenilda',
            'zenilda': 'Zenilda'
        }
        
        # Atualizar nomes no histórico
        for nome_antigo, nome_novo in mapeamento_nomes.items():
            cur = conn.execute(
                'SELECT COUNT(*) FROM historico_setor WHERE analista = ?',
                (nome_antigo,)
            )
            count = cur.fetchone()[0]
            if count > 0:
                conn.execute(
                    'UPDATE historico_setor SET analista = ? WHERE analista = ?',
                    (nome_novo, nome_antigo)
                )
                print(f"✓ Padronizado: {nome_antigo} → {nome_novo} ({count} registros)")
        
        conn.commit()
    except Exception as e:
        print(f"⚠ Erro ao padronizar nomes: {e}")

def tem_coluna(tabela, coluna):
    """Verificar se uma coluna existe em uma tabela."""
    conn = get_db()
    try:
        cursor = conn.execute(f"PRAGMA table_info({tabela})")
        columns = [col[1] for col in cursor.fetchall()]
    finally:
        conn.close()
    return coluna in columns

def corrigir_nomes_duplicados():
    """Função para corrigir nomes duplicados após a inicialização."""
    print("🔧 Executando correção de nomes duplicados...")
    conn = get_db()
    try:
        # Verificar se há nomes duplicados no histórico
        cur = conn.execute('''
            SELECT analista, COUNT(*) as total 
            FROM historico_setor 
            WHERE analista IS NOT NULL 
            GROUP BY LOWER(analista) 
            HAVING COUNT(DISTINCT analista) > 1
        ''')
        duplicados = cur.fetchall()
        
        if duplicados:
            print(f"🔍 Encontrados {len(duplicados)} grupos de nomes duplicados")
            
            # Aplicar correções específicas
            mapeamento_correcoes = {
                'BRUNO': 'Bruno',
                'bruno': 'Bruno',
                'ERICA': 'Erica', 
                'erica': 'Erica',
                'VANESSA': 'Vanessa',
                'vanessa': 'Vanessa',
                'ALESSANDRO': 'Alessandro',
                'alessandro': 'Alessandro',
                'CARMEN': 'Carmen',
                'carmen': 'Carmen',
                'ZENILDA': 'Zenilda',
                'zenilda': 'Zenilda'
            }
            
            total_corrigidos = 0
            for nome_errado, nome_correto in mapeamento_correcoes.items():
                cur = conn.execute(
                    'SELECT COUNT(*) FROM historico_setor WHERE analista = ?',
                    (nome_errado,)
                )
                count = cur.fetchone()[0]
                
                if count > 0:
                    conn.execute(
                        'UPDATE historico_setor SET analista = ? WHERE analista = ?',
                        (nome_correto, nome_errado)
                    )
                    total_corrigidos += count
                    print(f"✓ Corrigido: {nome_errado} → {nome_correto} ({count} registros)")
            
            if total_corrigidos > 0:
                conn.commit()
                print(f"✅ Total de {total_corrigidos} registros corrigidos!")
            else:
                print("ℹ Nenhuma correção necessária")
        else:
            print("✅ Nenhum nome duplicado encontrado")
            
    except Exception as e:
        print(f"⚠ Erro ao corrigir nomes duplicados: {e}")
    finally:
        conn.close()

def migrar_colunas_historico():
    """Migrar colunas do histórico para formato correto: SETOR_ORIGEM → ASSUNTO, valores originais do banco."""
    print("🔄 Executando migração corrigida de colunas do histórico...")
    conn = get_db()
    try:
        # Verificar se já foi executada a migração corrigida
        try:
            cur = conn.execute("SELECT valor FROM sistema_meta WHERE chave='migracao_colunas_corrigida'")
            row = cur.fetchone()
            if row and str(row[0]) == '1':
                print("ℹ Migração corrigida já foi executada anteriormente.")
                return
        except Exception:
            pass

        # Contar registros antes da migração
        cur = conn.execute('SELECT COUNT(*) FROM historico_setor')
        total_registros = cur.fetchone()[0]
        
        if total_registros == 0:
            print("ℹ Nenhum registro encontrado no histórico.")
            return

        print(f"🔍 Encontrados {total_registros} registros para migração corrigida...")

        # NOVA MIGRAÇÃO CORRIGIDA:
        # O que está em setor_origem (ex: "CTC") deve ir para assunto
        # O setor_origem deve voltar a ter os dados originais do banco
        # Para isso, vamos mover: setor_origem → assunto
        conn.execute('''
            UPDATE historico_setor SET
                assunto = COALESCE(setor_origem, ''),
                setor_origem = COALESCE(tipo_processo, '')
            WHERE id > 0
        ''')

        # Marcar como migrado com nova flag
        conn.execute(
            "INSERT OR REPLACE INTO sistema_meta (chave, valor, atualizado_em) VALUES ('migracao_colunas_corrigida','1',CURRENT_TIMESTAMP)"
        )
        
        conn.commit()
        print(f"✅ Migração CORRIGIDA concluída! {total_registros} registros atualizados.")
        print("✅ Setor Origem → Assunto")
        print("✅ Tipo Processo → Setor Origem")
        print("✅ Agora: ASSUNTO=CTC, SETOR_ORIGEM=STC, TIPO_PROCESSO=DIGITAL")
        
    except Exception as e:
        print(f"⚠ Erro na migração corrigida: {e}")
        conn.rollback()
    finally:
        conn.close()

# =============================================================================
# ROTAS PRINCIPAIS / AUTENTICAÇÃO
# =============================================================================
@app.route('/')
def index():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    if user['papel'] in ('gerente', 'admin'):
        return redirect(url_for('painel_gerencia'))
    return redirect(url_for('painel_analista'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        primeiro_nome = (request.form.get('primeiro_nome') or '').strip()
        senha = request.form.get('senha') or ''
        if not primeiro_nome or not senha:
            flash('Nome e senha são obrigatórios.', 'error')
            return render_template('login.html')

        conn = get_db()
        try:
            cursor = conn.execute(
                'SELECT id, senha_hash, papel FROM usuarios WHERE LOWER(primeiro_nome) = LOWER(?) AND ativo = 1',
                (primeiro_nome,)
            )
            row = cursor.fetchone()
        finally:
            conn.close()

        if row and check_password_hash(row[1], senha):
            session['user_id'] = row[0]
            session['user_papel'] = row[2]
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
# CENTRAL DE ESTATÍSTICAS (UM HANDLER, DOIS ENDPOINTS/URLs)
# =============================================================================

@app.route('/debug-estatisticas')
@login_required
@role_required('gerente', 'admin')
def debug_estatisticas():
    """Página de debug para estatísticas."""
    return render_template('debug_estatisticas.html')

@app.route('/central-estatisticas-clean')
@login_required
@role_required('gerente', 'admin')
def central_estatisticas_clean():
    """Central de estatísticas - versão limpa para teste."""
    conn = get_db()
    try:
        cursor = conn.execute(
            "SELECT id, primeiro_nome FROM usuarios WHERE papel = 'analista' AND ativo = 1 ORDER BY primeiro_nome"
        )
        analistas = [{'id': r[0], 'primeiro_nome': r[1]} for r in cursor.fetchall()]
    finally:
        conn.close()
    return render_template('central_estatisticas_clean.html', analistas=analistas)

@app.route('/central-estatisticas', endpoint='central_estatisticas')
@app.route('/painel-gerencia/estatisticas', endpoint='central_estatisticas_page')  # compat
@login_required
@role_required('gerente', 'admin')
def central_estatisticas():
    """Central de estatísticas (template usa API para dados)."""
    conn = get_db()
    try:
        cursor = conn.execute(
            "SELECT id, primeiro_nome FROM usuarios WHERE papel = 'analista' AND ativo = 1 ORDER BY primeiro_nome"
        )
        analistas = [{'id': r[0], 'primeiro_nome': r[1]} for r in cursor.fetchall()]
    finally:
        conn.close()
    return render_template('central_estatisticas.html', analistas=analistas)

# =============================================================================
# PAINEL DE GERÊNCIA
# =============================================================================

@app.route('/painel-gerencia')
@login_required
@role_required('gerente', 'admin')
def painel_gerencia():
    """Painel de gerência com visão de atribuição."""
    conn = get_db()
    try:
        # Analistas ativos
        cur = conn.execute(
            "SELECT id, primeiro_nome FROM usuarios WHERE papel = 'analista' AND ativo = 1 ORDER BY primeiro_nome"
        )
        analistas = [{'id': r[0], 'primeiro_nome': r[1]} for r in cur.fetchall()]

        # Processos não atribuídos
        cur = conn.execute('''
            SELECT id, numero, titulo, descricao, status, criado_em 
            FROM processos 
            WHERE analista_id IS NULL AND status != 'cancelado'
            ORDER BY criado_em DESC
        ''')
        processos_nao_atribuidos = [
            {
                'id': r[0], 'numero': r[1], 'titulo': r[2], 'descricao': r[3],
                'status': r[4], 'criado_em': r[5]
            } for r in cur.fetchall()
        ]

        # Carga de trabalho por analista
        carga_trabalho = {}
        for a in analistas:
            cur = conn.execute('''
                SELECT COUNT(*) FROM processos 
                WHERE analista_id = ? AND status IN ('novo', 'em_analise', 'aguardando')
            ''', (a['id'],))
            carga_trabalho[a['id']] = cur.fetchone()[0]

        # Processos atribuídos nas últimas 24h
        processos_recentes = []
        if tem_coluna('processos', 'data_atribuicao'):
            data_limite = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
            cur = conn.execute('''
                SELECT p.id, p.numero, p.titulo, p.data_atribuicao, u.primeiro_nome
                FROM processos p
                LEFT JOIN usuarios u ON p.analista_id = u.id
                WHERE p.data_atribuicao IS NOT NULL AND p.data_atribuicao >= ?
                ORDER BY p.data_atribuicao DESC
                LIMIT 10
            ''', (data_limite,))
            for r in cur.fetchall():
                processos_recentes.append({
                    'id': r[0], 'numero': r[1], 'titulo': r[2],
                    'data_atribuicao': datetime.strptime(r[3], '%Y-%m-%d %H:%M:%S') if r[3] else None,
                    'analista': {'primeiro_nome': r[4]} if r[4] else None
                })
    finally:
        conn.close()

    return render_template('painel_gerencia.html',
                           analistas=analistas,
                           processos_nao_atribuidos=processos_nao_atribuidos,
                           carga_trabalho=carga_trabalho,
                           processos_recentes=processos_recentes)

# Decorator interno (apenas gerência) para algumas APIs
def only_gerencia(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_papel') not in ('gerente', 'admin'):
            flash('Acesso restrito à gerência.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/painel-gerencia/historico')
@login_required
@role_required('gerente', 'admin')
def painel_historico():
    pagina = request.args.get('pagina', 1, type=int)
    por_pagina = 100
    offset = (pagina - 1) * por_pagina

    # Filtros
    q = (request.args.get('q') or '').strip()
    analista = (request.args.get('analista') or '').strip()
    data_inicio = (request.args.get('data_inicio') or '').strip()
    data_fim = (request.args.get('data_fim') or '').strip()

    filtros, params = [], []
    if q:
        filtros.append("interessado LIKE ?")
        params.append(f"%{q}%")
    if analista:
        filtros.append("analista = ?")
        params.append(analista)
    if data_inicio:
        filtros.append("data_distribuicao >= ?")
        params.append(data_inicio)
    if data_fim:
        filtros.append("data_distribuicao <= ?")
        params.append(data_fim)

    where_clause = ("WHERE " + " AND ".join(filtros)) if filtros else ""

    conn = get_db()
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM historico_setor {where_clause}", params).fetchone()[0]
        cur = conn.execute(f'''
            SELECT id, ordem, analista, numero, data_distribuicao, data_conclusao,
                   interessado, assunto, setor_origem, tipo_processo, status_processo, criado_em
            FROM historico_setor
            {where_clause}
            ORDER BY data_distribuicao DESC, id DESC
            LIMIT ? OFFSET ?
        ''', (*params, por_pagina, offset))
        rows = [{
            'id': r[0], 'ordem': r[1], 'analista': r[2], 'numero': r[3],
            'data_distribuicao': r[4], 'data_conclusao': r[5], 'interessado': r[6],
            'assunto': r[7], 'setor_origem': r[8], 'tipo_processo': r[9], 
            'status_processo': r[10], 'criado_em': r[11]
        } for r in cur.fetchall()]

        analistas = [r[0] for r in conn.execute(
            "SELECT DISTINCT analista FROM historico_setor WHERE analista IS NOT NULL ORDER BY analista"
        ).fetchall()]
    finally:
        conn.close()

    total_paginas = (total + por_pagina - 1) // por_pagina

    return render_template('painel_historico.html',
                           rows=rows,
                           pagina=pagina,
                           total_paginas=total_paginas,
                           analistas=analistas)

# =============================================================================
# PAINEL DO ANALISTA
# =============================================================================
@app.route('/api/processo/<int:processo_id>/status', methods=['POST'])
@login_required
def api_atualizar_status(processo_id):
    data = request.get_json() or {}
    novo_status = data.get('status')

    if not novo_status:
        return jsonify({'success': False, 'message': 'Status obrigatório'}), 400

    conn = get_db()
    try:
        # Buscar dados do processo e status anterior
        cur = conn.execute('''
            SELECT numero, titulo, status, analista_id 
            FROM processos 
            WHERE id = ?
        ''', (processo_id,))
        processo = cur.fetchone()
        
        if not processo:
            return jsonify({'success': False, 'message': 'Processo não encontrado'}), 404
            
        numero, titulo, status_anterior, analista_id = processo
        
        # Atualiza na tabela principal
        conn.execute(
            'UPDATE processos SET status = ?, atualizado_em = CURRENT_TIMESTAMP WHERE id = ?',
            (novo_status, processo_id)
        )

        # Atualiza também no histórico
        if numero:
            conn.execute(
                'UPDATE historico_setor SET status_processo = ? WHERE numero = ?',
                (novo_status, numero)
            )

        # Criar notificação para gerentes se houve mudança de status
        if status_anterior != novo_status and analista_id:
            user = get_current_user()
            if user and user['papel'] == 'analista':
                # Buscar gerentes para notificar
                cur = conn.execute('''
                    SELECT id FROM usuarios 
                    WHERE papel IN ('gerente', 'admin') AND ativo = 1
                ''')
                gerentes = cur.fetchall()
                
                # Mapear status para exibição
                status_map = {
                    'novo': 'Novo',
                    'em_analise': 'Em Análise', 
                    'aguardando': 'Aguardando',
                    'aguardando_chamado': 'Aguardando Chamado',
                    'aguardando_orientacao': 'Aguardando Orientação',
                    'sobrestado': 'Sobrestado',
                    'concluido': 'Concluído'
                }
                
                status_anterior_nome = status_map.get(status_anterior, status_anterior)
                status_novo_nome = status_map.get(novo_status, novo_status)
                
                titulo_notif = f"Status alterado: {titulo}"
                mensagem_notif = f"{user['primeiro_nome']} alterou o status do processo {numero} ({titulo}) de '{status_anterior_nome}' para '{status_novo_nome}'"
                
                for gerente in gerentes:
                    conn.execute('''
                        INSERT INTO notificacoes 
                        (usuario_destino_id, usuario_origem_id, tipo, titulo, mensagem, 
                         processo_numero, status_anterior, status_novo)
                        VALUES (?, ?, 'status_change', ?, ?, ?, ?, ?)
                    ''', (gerente[0], user['id'], titulo_notif, mensagem_notif, 
                          numero, status_anterior, novo_status))

        conn.commit()
    finally:
        conn.close()

    return jsonify({'success': True, 'message': 'Status atualizado com sucesso'})

@app.route('/painel-analista')
@login_required
def painel_analista():
    user = get_current_user()
    conn = get_db()
    try:
        cur = conn.execute('''
           SELECT id, numero, titulo, descricao, status, observacoes, criado_em
           FROM processos 
           WHERE analista_id = ? 
           ORDER BY 
                 CASE status 
                     WHEN 'novo' THEN 1 
                     WHEN 'em_analise' THEN 2 
                     WHEN 'aguardando' THEN 3 
                     WHEN 'concluido' THEN 4 
                 END,
                 criado_em DESC
         ''', (user['id'],))

        processos = [{
           'id': r[0], 'numero': r[1], 'titulo': r[2], 'descricao': r[3],
           'status': r[4], 'observacoes': r[5], 'criado_em': r[6]
        } for r in cur.fetchall()]

    finally:
        conn.close()

    stats = {
        'total': len(processos),
        'novo': len([p for p in processos if p['status'] == 'novo']),
        'em_analise': len([p for p in processos if p['status'] == 'em_analise']),
        'aguardando': len([p for p in processos if p['status'] == 'aguardando']),
        'concluido': len([p for p in processos if p['status'] == 'concluido']),
    }
    return render_template('painel_analista.html', processos=processos, stats=stats)

# =============================================================================
# DASHBOARD (COMPATIBILIDADE)
# =============================================================================

@app.route('/dashboard')
@login_required
@role_required('gerente', 'admin')
def dashboard():
    return redirect(url_for('painel_gerencia'))

# =============================================================================
# APIs (SEM EMAIL)
# =============================================================================

@app.route('/api/historico/update/<int:id>', methods=['POST'])
@login_required
@only_gerencia
def api_update_processo(id):
    data = request.json
    conn = get_db()
    try:
        conn.execute('''
            UPDATE historico_setor SET
                ordem = ?, analista = ?, numero = ?, data_distribuicao = ?,
                data_conclusao = ?, interessado = ?, assunto = ?,
                setor_origem = ?, tipo_processo = ?, status_processo = ?
            WHERE id = ?
        ''', (
            data.get('ordem'),
            data.get('analista'),
            data.get('numero'),
            data.get('data_distribuicao'),
            data.get('data_conclusao'),
            data.get('interessado'),
            data.get('assunto'),
            data.get('setor_origem'),
            data.get('tipo_processo'),
            data.get('status_processo'),
            id
        ))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'success': True})

@app.route('/api/distribuir', methods=['POST'])
@login_required
@only_gerencia
def distribuir_processo():
    data = request.json
    conn = get_db()
    try:
        # Obter próxima ordem automática
        cur = conn.execute('SELECT COALESCE(MAX(ordem), 0) + 1 FROM historico_setor')
        proxima_ordem = cur.fetchone()[0]
        
        conn.execute('''
            INSERT INTO historico_setor (
                ordem, analista, numero, data_distribuicao,
                interessado, assunto, setor_origem, tipo_processo, status_processo
            ) VALUES (?, ?, ?, date('now'), ?, ?, ?, ?, ?)
        ''', (
            proxima_ordem,
            data.get('analista'),
            data.get('numero'),
            data.get('interessado'),
            data.get('assunto'),
            data.get('setor_origem'),
            data.get('tipo_processo', ''),
            data.get('status_processo', 'novo')
        ))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'success': True})

@app.route('/api/processo/criar', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_criar_processo():
    try:
        data = request.get_json() or {}
        numero = (data.get('numero') or '').strip()
        titulo = (data.get('titulo') or '').strip()
        descricao = (data.get('descricao') or '').strip()
        assunto = (data.get('assunto') or '').strip().upper()
        setor_origem = (data.get('setor_origem') or '').strip().upper()
        tipo_processo = (data.get('tipo_processo') or '').strip()
        analista_nome = (data.get('analista_nome') or '').strip()

        if not numero or not titulo or not assunto or not setor_origem or not tipo_processo:
            return jsonify({'success': False, 'message': 'Número, título, assunto, setor de origem e tipo de processo são obrigatórios'})

        conn = get_db()
        # duplicidade
        cur = conn.execute('SELECT id FROM processos WHERE numero = ?', (numero,))
        if cur.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Número do processo já existe'})

        analista_id = None
        if analista_nome:
            cur = conn.execute(
                'SELECT id FROM usuarios WHERE LOWER(primeiro_nome) = LOWER(?) AND papel = "analista" AND ativo = 1',
                (analista_nome,)
            )
            r = cur.fetchone()
            if r:
                analista_id = r[0]

        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # MODIFICADO: Incluir assunto, setor_origem e tipo_processo na inserção
        if tem_coluna('processos', 'data_atribuicao') and analista_id:
            cur = conn.execute('''
                INSERT INTO processos (numero, titulo, descricao, analista_id, data_atribuicao, assunto, setor_origem, tipo_processo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (numero, titulo, descricao, analista_id, now_ts, assunto, setor_origem, tipo_processo))
        else:
            cur = conn.execute('''
                INSERT INTO processos (numero, titulo, descricao, analista_id, assunto, setor_origem, tipo_processo)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (numero, titulo, descricao, analista_id, assunto, setor_origem, tipo_processo))

        processo_id = cur.lastrowid

        # histórico (se já atribuído)
        if analista_id:
            try:
                data_dist = now_ts.split(' ')[0]
                
                # Obter próxima ordem automática
                cur = conn.execute('SELECT COALESCE(MAX(ordem), 0) + 1 FROM historico_setor')
                proxima_ordem = cur.fetchone()[0]
                
                conn.execute('''
                    INSERT INTO historico_setor (ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (proxima_ordem, analista_nome, numero, data_dist, None, titulo, assunto, setor_origem, tipo_processo, 'novo'))
            except Exception as e:
                print(f"Erro ao inserir no histórico: {e}")

        conn.commit()
        conn.close()

        processo = {
            'id': processo_id,
            'numero': numero,
            'titulo': titulo,
            'descricao': descricao,
            'status': 'novo',
            'analista_id': analista_id,
            'assunto': assunto,
            'setor_origem': setor_origem,
            'tipo_processo': tipo_processo
        }
        return jsonify({'success': True, 'message': 'Processo criado com sucesso', 'processo': processo})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/atribuir', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_atribuir_processo(processo_id):
    try:
        data = request.get_json() or {}
        analista_nome = (data.get('analista_nome') or '').strip()
        analista_id = data.get('analista_id')

        if not analista_nome and not analista_id:
            return jsonify({'success': False, 'message': 'Analista obrigatório'})

        conn = get_db()
        # buscar por nome se necessário
        if analista_nome and not analista_id:
            cur = conn.execute(
                'SELECT id FROM usuarios WHERE LOWER(primeiro_nome) = LOWER(?) AND papel = "analista" AND ativo = 1',
                (analista_nome,)
            )
            r = cur.fetchone()
            if not r:
                conn.close()
                return jsonify({'success': False, 'message': 'Analista não encontrado'})
            analista_id = r[0]

        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if tem_coluna('processos', 'data_atribuicao'):
            conn.execute(
                'UPDATE processos SET analista_id = ?, data_atribuicao = ?, status = ? WHERE id = ?',
                (analista_id, now_ts, 'em_analise', processo_id)
            )
        else:
            conn.execute(
                'UPDATE processos SET analista_id = ?, status = ? WHERE id = ?',
                (analista_id, 'em_analise', processo_id)
            )

        # dados do processo para histórico
        cur = conn.execute('SELECT numero, titulo, descricao, assunto, setor_origem, tipo_processo FROM processos WHERE id = ?', (processo_id,))
        proc = cur.fetchone()
        numero = proc[0] if proc else ''
        titulo = proc[1] if proc and len(proc) > 1 else ''
        # Usar os valores do processo, com fallbacks para garantir que não quebre
        assunto = proc[3] if proc and proc[3] else ''
        setor_origem = proc[4] if proc and proc[4] else ''
        tipo_processo = proc[5] if proc and proc[5] else ''

        try:
            if not analista_nome:
                cur = conn.execute('SELECT primeiro_nome FROM usuarios WHERE id = ?', (analista_id,))
                arow = cur.fetchone()
                analista_nome = arow[0] if arow else ''
            data_dist = now_ts.split(' ')[0]
            
            # Obter próxima ordem automática
            cur = conn.execute('SELECT COALESCE(MAX(ordem), 0) + 1 FROM historico_setor')
            proxima_ordem = cur.fetchone()[0]
            
            # Para processos atribuídos posteriormente, usar valores padrão para os novos campos
            conn.execute('''
                INSERT INTO historico_setor (ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (proxima_ordem, analista_nome, numero, data_dist, None, titulo, assunto, setor_origem, tipo_processo, 'em_analise'))
        except Exception as e:
            print(f"Erro ao inserir no histórico: {e}")
            pass

        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': f'Processo atribuído para {analista_nome}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/editar', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_editar_processo(processo_id):
    """Editar dados básicos de um processo (apenas gerência)."""
    try:
        data = request.get_json() or {}
        numero = (data.get('numero') or '').strip()
        titulo = (data.get('titulo') or '').strip()
        descricao = (data.get('descricao') or '').strip()

        if not numero or not titulo:
            return jsonify({'success': False, 'message': 'Número e título são obrigatórios'})

        conn = get_db()
        
        # Verificar se o processo existe
        cur = conn.execute('SELECT id, numero FROM processos WHERE id = ?', (processo_id,))
        processo = cur.fetchone()
        if not processo:
            conn.close()
            return jsonify({'success': False, 'message': 'Processo não encontrado'})

        numero_antigo = processo[1]

        # Verificar duplicidade (exceto o próprio processo)
        cur = conn.execute('SELECT id FROM processos WHERE numero = ? AND id != ?', (numero, processo_id))
        if cur.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Número do processo já existe'})

        # Atualizar dados do processo
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('''
            UPDATE processos 
            SET numero = ?, titulo = ?, descricao = ?, atualizado_em = ?
            WHERE id = ?
        ''', (numero, titulo, descricao, now_ts, processo_id))

        # Atualizar também no histórico se o número mudou
        if numero_antigo != numero:
            try:
                conn.execute('''
                    UPDATE historico_setor 
                    SET numero = ?, interessado = ?, assunto = ?
                    WHERE numero = ?
                ''', (numero, titulo, descricao, numero_antigo))
            except Exception:
                pass  # Ignore se não conseguir atualizar histórico

        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'Processo editado com sucesso'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/reverter-atribuicao', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_reverter_atribuicao(processo_id):
    """Reverter atribuição de um processo - volta para não distribuídos e remove do histórico."""
    try:
        conn = get_db()
        
        # Verificar se o processo existe e está atribuído
        cur = conn.execute('''
            SELECT p.id, p.numero, p.titulo, p.analista_id, u.primeiro_nome
            FROM processos p
            LEFT JOIN usuarios u ON p.analista_id = u.id
            WHERE p.id = ?
        ''', (processo_id,))
        
        processo = cur.fetchone()
        if not processo:
            conn.close()
            return jsonify({'success': False, 'message': 'Processo não encontrado'})
        
        if not processo[3]:  # analista_id
            conn.close()
            return jsonify({'success': False, 'message': 'Processo já não está atribuído'})
        
        numero = processo[1]
        titulo = processo[2]
        analista_nome = processo[4]
        
        # Remover atribuição do processo
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('''
            UPDATE processos 
            SET analista_id = NULL, 
                data_atribuicao = NULL, 
                status = 'novo',
                atualizado_em = ?
            WHERE id = ?
        ''', (now_ts, processo_id))
        
        # REMOVER completamente do histórico do setor
        registros_removidos = 0
        try:
            # Primeiro verificar quantos registros existem ANTES da remoção
            cur = conn.execute('''
                SELECT id FROM historico_setor 
                WHERE numero = ? AND LOWER(analista) = LOWER(?)
            ''', (numero, analista_nome))
            
            registros_encontrados = cur.fetchall()
            print(f"Debug: Encontrados {len(registros_encontrados)} registros para processo {numero} - analista {analista_nome}")
            
            for registro in registros_encontrados:
                print(f"Debug: Registro ID {registro[0]} será removido")
            
            # Remover TODOS os registros do histórico para este processo e analista
            # (tanto concluídos quanto não concluídos)
            conn.execute('''
                DELETE FROM historico_setor 
                WHERE numero = ? AND LOWER(analista) = LOWER(?)
            ''', (numero, analista_nome))
            
            # Verificar quantos foram realmente removidos
            registros_removidos = len(registros_encontrados)
            
            print(f"Debug: Removidos {registros_removidos} registros do histórico")
            
            # Verificar se ainda há registros
            cur = conn.execute('''
                SELECT COUNT(*) FROM historico_setor 
                WHERE numero = ? AND LOWER(analista) = LOWER(?)
            ''', (numero, analista_nome))
            
            restantes = cur.fetchone()[0]
            print(f"Debug: Registros restantes após remoção: {restantes}")
            
        except Exception as e:
            print(f"Erro ao remover do histórico: {e}")
            # Não falhar a operação principal por isso
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': f'Processo {numero} revertido com sucesso. Voltou para não distribuídos e foi removido do histórico ({registros_removidos} registros removidos).',
            'historico_removido': registros_removidos > 0,
            'registros_removidos': registros_removidos
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro ao reverter atribuição: {str(e)}'})

@app.route('/api/processo/<int:processo_id>/atualizar', methods=['POST', 'PUT'])
@login_required
def api_atualizar_processo(processo_id):
    try:
        data = request.get_json() or {}
        user = get_current_user()
        conn = get_db()

        # permissão: analista só nos seus processos
        cur = conn.execute('SELECT analista_id FROM processos WHERE id = ?', (processo_id,))
        row = cur.fetchone()
        if user['papel'] == 'analista':
            if not row or row[0] != user['id']:
                conn.close()
                return jsonify({'success': False, 'message': 'Permissão negada para atualizar este processo'}), 403

        updates, params = [], []
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if 'status' in data:
            updates.append('status = ?')
            params.append(data.get('status'))
            if data.get('status') == 'concluido' and tem_coluna('processos', 'data_conclusao'):
                updates.append('data_conclusao = ?')
                params.append(now_ts)

        if 'observacoes' in data:
            updates.append('observacoes = ?')
            params.append(data.get('observacoes'))

        if updates:
            updates.append('atualizado_em = ?')
            params.append(now_ts)
            params.append(processo_id)
            sql = 'UPDATE processos SET ' + ', '.join(updates) + ' WHERE id = ?'
            conn.execute(sql, tuple(params))
            conn.commit()

            if 'status' in data and data.get('status') == 'concluido':
                try:
                    cur = conn.execute('SELECT numero FROM processos WHERE id = ?', (processo_id,))
                    proc = cur.fetchone()
                    numero = proc[0] if proc else None
                    if numero:
                        conn.execute('''
                            UPDATE historico_setor
                            SET data_conclusao = ?, status_processo = ?
                            WHERE numero = ? AND (data_conclusao IS NULL OR data_conclusao = '')
                        ''', (now_ts.split(' ')[0], 'concluido', numero))
                        conn.commit()
                except Exception:
                    pass
            elif 'status' in data:
                # Atualizar status no histórico para qualquer mudança de status
                try:
                    cur = conn.execute('SELECT numero FROM processos WHERE id = ?', (processo_id,))
                    proc = cur.fetchone()
                    numero = proc[0] if proc else None
                    if numero:
                        # Mapear status do sistema para status legível
                        status_map = {
                            'novo': 'novo',
                            'em_analise': 'em_analise',
                            'aguardando': 'aguardando_orientacao',
                            'aguardando_chamado': 'aguardando_chamado',
                            'sobrestado': 'sobrestado',
                            'concluido': 'concluido'
                        }
                        status_historico = status_map.get(data.get('status'), data.get('status'))
                        
                        conn.execute('''
                            UPDATE historico_setor
                            SET status_processo = ?
                            WHERE numero = ? AND status_processo != 'concluido'
                        ''', (status_historico, numero))
                        conn.commit()
                except Exception:
                    pass

        conn.close()
        return jsonify({'success': True, 'message': 'Processo atualizado com sucesso'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro: {str(e)}'})

@app.route('/api/historico/import', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_historico_import():
    """Importar lista de registros (JSON array) para historico_setor."""
    try:
        data = request.get_json() or {}
        records = data if isinstance(data, list) else data.get('rows', [])
        conn = get_db()
        inserted = 0
        for r in records:
            conn.execute('''
                INSERT INTO historico_setor (ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                r.get('ordem'), r.get('analista'), r.get('numero'), r.get('data_distribuicao'),
                r.get('data_conclusao'), r.get('interessado'), r.get('assunto'), r.get('setor_origem'), 
                r.get('tipo_processo'), r.get('status_processo')
            ))
            inserted += 1
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'inserted': inserted})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/historico/list')
@login_required
@role_required('gerente', 'admin')
def api_historico_list():
    conn = get_db()
    try:
        cur = conn.execute('''
            SELECT id, ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo, criado_em
            FROM historico_setor
            ORDER BY data_distribuicao DESC, id DESC
        ''')
        rows = [{
            'id': r[0], 'ordem': r[1], 'analista': r[2], 'numero': r[3],
            'data_distribuicao': r[4], 'data_conclusao': r[5], 'interessado': r[6],
            'assunto': r[7], 'setor_origem': r[8], 'tipo_processo': r[9], 
            'status_processo': r[10], 'criado_em': r[11]
        } for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify({'success': True, 'rows': rows})

@app.route('/api/historico/add', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_historico_add():
    try:
        data = request.get_json()
        print(f"Debug: Dados recebidos para novo registro: {data}")
        
        analista = (data.get('analista') or '').strip()
        numero = (data.get('numero') or '').strip()
        data_distribuicao = data.get('data_distribuicao') or ''
        data_conclusao = data.get('data_conclusao')
        interessado = (data.get('interessado') or '').strip()
        assunto = (data.get('assunto') or '').strip()
        setor_origem = (data.get('setor_origem') or '').strip()
        tipo_processo = (data.get('tipo_processo') or '').strip()
        status_processo = (data.get('status_processo') or '').strip()

        if not analista or not numero or not interessado:
            return jsonify({'success': False, 'message': 'Analista, número do processo e interessado são obrigatórios'})

        conn = get_db()
        try:
            # Verificar duplicatas
            if numero:
                cur = conn.execute(
                    """
                    SELECT id FROM historico_setor 
                    WHERE numero = ? 
                      AND IFNULL(data_distribuicao,'') = ?
                      AND IFNULL(LOWER(analista),'') = LOWER(?)
                    LIMIT 1
                    """,
                    (numero, data_distribuicao, analista)
                )
                if cur.fetchone():
                    return jsonify({'success': False, 'message': 'Registro duplicado (mesmo número, data e analista).'})
            
            # Obter próxima ordem automática
            cur = conn.execute('SELECT COALESCE(MAX(ordem), 0) + 1 FROM historico_setor')
            proxima_ordem = cur.fetchone()[0]
            
            print(f"Debug: Inserindo registro - Ordem: {proxima_ordem}, Analista: {analista}, Número: {numero}")
            
            cur = conn.execute('''
                INSERT INTO historico_setor (ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (proxima_ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo))
            new_id = cur.lastrowid
            conn.commit()
            
            print(f"Debug: Registro inserido com sucesso - ID: {new_id}")
            
        finally:
            conn.close()

        return jsonify({'success': True, 'id': new_id, 'ordem': proxima_ordem, 'message': 'Registro adicionado com sucesso'})
    except Exception as e:
        print(f"Erro ao adicionar registro: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/historico/delete/<int:row_id>', methods=['POST', 'DELETE'])
@login_required
@role_required('gerente', 'admin')
def api_historico_delete(row_id):
    """Excluir um registro específico do histórico do setor e o processo correspondente."""
    try:
        conn = get_db()
        
        # Primeiro verificar se o registro existe
        cur = conn.execute('SELECT id, numero, analista FROM historico_setor WHERE id = ?', (row_id,))
        registro = cur.fetchone()
        
        if not registro:
            conn.close()
            return jsonify({'success': False, 'message': 'Registro não encontrado'})
        
        numero = registro[1]
        analista = registro[2]
        
        # Excluir TAMBÉM o processo da tabela processos (se existir)
        processo_removido = False
        if numero:
            try:
                # Verificar se existe processo com este número
                cur = conn.execute('SELECT id FROM processos WHERE numero = ?', (numero,))
                processo = cur.fetchone()
                
                if processo:
                    processo_id = processo[0]
                    # Remover o processo da tabela processos
                    conn.execute('DELETE FROM processos WHERE id = ?', (processo_id,))
                    processo_removido = True
                    print(f"Debug: Processo {numero} (ID: {processo_id}) removido da tabela processos")
            except Exception as e:
                print(f"Aviso: Erro ao remover processo {numero}: {e}")
                # Continua a execução mesmo se não conseguir remover o processo
        
        # Excluir o registro do histórico
        conn.execute('DELETE FROM historico_setor WHERE id = ?', (row_id,))
        
        conn.commit()
        conn.close()
        
        print(f"Debug: Registro {row_id} excluído - Processo {numero} - Analista {analista}")
        
        # Mensagem personalizada dependendo do que foi removido
        if processo_removido:
            message = f'Registro do processo {numero} ({analista}) excluído completamente do sistema (histórico + painel de gerência)'
        else:
            message = f'Registro do processo {numero} ({analista}) excluído do histórico'
        
        return jsonify({
            'success': True, 
            'message': message,
            'deleted_id': row_id,
            'processo_removido': processo_removido,
            'numero_processo': numero
        })
        
    except Exception as e:
        print(f"Erro ao excluir registro {row_id}: {e}")
        return jsonify({'success': False, 'message': f'Erro ao excluir: {str(e)}'})

@app.route('/api/historico/upload', methods=['POST'])
@login_required
@role_required('gerente', 'admin')
def api_historico_upload():
    """Upload CSV/XLSX com histórico. Insere em historico_setor."""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'Nenhum arquivo enviado'}), 400
        f = request.files['file']
        filename = (f.filename or '').lower()

        # Leitura
        if filename.endswith('.csv'):
            content = f.stream.read().decode('utf-8', errors='ignore')
            stream = io.StringIO(content)
            reader = csv.DictReader(stream)
            records = [row for row in reader]
        elif filename.endswith(('.xlsx', '.xls')):
            if openpyxl is None:
                return jsonify({'success': False, 'message': 'openpyxl não está disponível para ler XLSX'}), 500
            wb = openpyxl.load_workbook(f, read_only=True)
            ws = wb.active
            it = ws.iter_rows(values_only=True)
            headers = [str(h).strip() if h is not None else '' for h in next(it)]
            records = []
            for row in it:
                obj = {}
                for i, val in enumerate(row):
                    if i < len(headers):
                        obj[headers[i]] = val
                records.append(obj)
        else:
            return jsonify({'success': False, 'message': 'Formato não suportado. Envie CSV ou XLSX.'}), 400

        # map helpers
        def find_value(row, candidates):
            for k in row.keys():
                kn = str(k).lower().strip()
                for c in candidates:
                    if c in kn:
                        return row.get(k)
            return None

        def normalize_date(v):
            if v is None:
                return None
            if isinstance(v, datetime):
                return v.strftime('%Y-%m-%d')
            s = str(v).strip()
            if not s:
                return None
            for fmt in ('%d/%m/%Y', '%Y-%m-%d', '%d-%m-%Y'):
                try:
                    return datetime.strptime(s, fmt).strftime('%Y-%m-%d')
                except Exception:
                    continue
            return s

        mapped = []
        for r in records:
            ordem = find_value(r, ['ordem', 'order'])
            analista = find_value(r, ['analista', 'analyst', 'responsavel', 'responsável'])
            numero = find_value(r, ['numero', 'nº', 'número', 'num']) or find_value(r, ['processo'])
            data_distribuicao = find_value(r, ['distribu', 'data distribu', 'data distribuição', 'data distrib']) or find_value(r, ['data'])
            data_conclusao = find_value(r, ['conclus', 'data conclusão', 'data conclu'])
            interessado = find_value(r, ['interess', 'interessado', 'interested'])
            assunto = find_value(r, ['assunto', 'subject'])
            setor_origem = find_value(r, ['setor origem', 'setor_origem', 'origem'])
            tipo_processo = find_value(r, ['tipo processo', 'tipo_processo', 'tipo']) or find_value(r, ['setor destino', 'destino', 'setor_destino'])
            status_processo = find_value(r, ['status processo', 'status_processo', 'status'])

            mapped.append({
                'ordem': ordem,
                'analista': (analista or '').strip() if isinstance(analista, str) else (analista or None),
                'numero': str(numero).strip() if numero is not None else None,
                'data_distribuicao': normalize_date(data_distribuicao),
                'data_conclusao': normalize_date(data_conclusao),
                'interessado': interessado,
                'assunto': assunto,
                'setor_origem': setor_origem,
                'tipo_processo': tipo_processo,
                'status_processo': status_processo
            })

        conn = get_db()
        try:
            inserted = 0
            for item in mapped:
                try:
                    numero = (item.get('numero') or '').strip()
                    analista = (item.get('analista') or '').strip()
                    data_dist = (item.get('data_distribuicao') or '').strip()
                    if numero:
                        exists = conn.execute(
                            """
                            SELECT id FROM historico_setor 
                            WHERE numero = ?
                              AND IFNULL(data_distribuicao,'') = ?
                              AND IFNULL(LOWER(analista),'') = LOWER(?)
                            LIMIT 1
                            """,
                            (numero, data_dist, analista)
                        ).fetchone()
                        if exists:
                            continue

                    conn.execute('''
                        INSERT INTO historico_setor (ordem, analista, numero, data_distribuicao, data_conclusao, interessado, assunto, setor_origem, tipo_processo, status_processo)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        item.get('ordem'), item.get('analista'), item.get('numero'), item.get('data_distribuicao'),
                        item.get('data_conclusao'), item.get('interessado'), item.get('assunto'), item.get('setor_origem'), 
                        item.get('tipo_processo'), item.get('status_processo')
                    ))
                    inserted += 1
                except Exception:
                    continue
            conn.commit()
        finally:
            conn.close()

        return jsonify({'success': True, 'inserted': inserted, 'total_rows': len(mapped)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# =============================================================================
# ROTA DE TESTE PARA DEBUG DE ESTATÍSTICAS
# =============================================================================

@app.route('/sar/api/test-estatisticas')
@login_required
@role_required('gerente', 'admin')
def test_estatisticas():
    """Teste básico para verificar dados do histórico."""
    try:
        conn = get_db()
        
        # Teste 1: Contar total de registros
        cur = conn.execute('SELECT COUNT(*) FROM historico_setor')
        total_registros = cur.fetchone()[0]
        
        # Teste 2: List
        cur = conn.execute('SELECT DISTINCT analista FROM historico_setor WHERE analista IS NOT NULL ORDER BY analista')
        analistas = [row[0] for row in cur.fetchall()]
        
        # Teste 3: Contar por analista
        cur = conn.execute('''
            SELECT analista, COUNT(*) as total
            FROM historico_setor 
            WHERE analista IS NOT NULL
            GROUP BY analista
            ORDER BY total DESC
        ''')
        por_analista = {row[0]: row[1] for row in cur.fetchall()}

        
        # Teste 4: Verificar estrutura da tabela
        cur = conn.execute('PRAGMA table_info(historico_setor)')
        colunas = [row[1] for row in cur.fetchall()]
        
        # Teste 5: Amostra de dados
        cur = conn.execute('''
            SELECT analista, numero, data_distribuicao, data_conclusao
            FROM historico_setor 
            WHERE id > 0
            ORDER BY id DESC 
            LIMIT 5
        ''')
        amostra = [{'analista': row[0], 'numero': row[1], 'data_distribuicao': row[2], 'data_conclusao': row[3]} for row in cur.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'debug': {
                'total_registros': total_registros,
                'analistas_unicos': analistas,
                'count_por_analista': por_analista,
                'colunas_tabela': colunas,
                'amostra_dados': amostra
            }
        })
        
    except Exception as e:
        import traceback

        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        })

# =============================================================================
# APIS PARA NOTIFICAÇÕES
# =============================================================================

@app.route('/sar/api/estatisticas-tempo-real')
@login_required
@role_required('gerente', 'admin')
def api_estatisticas_tempo_real():
    """
    API principal para estatísticas em tempo real da Central de Estatísticas.
    """
    try:
        # CORREÇÃO: Obter parâmetros da requisição
        periodo = request.args.get('periodo', 'semana')
        analista_filtro = request.args.get('analista')
        data_inicio = request.args.get('data_inicio')
        data_fim = request.args.get('data_fim')

        conn = get_db()
        
        # CORREÇÃO: Usar a função auxiliar para montar a cláusula WHERE
        where_clause, params = _periodo_where_for_historico(periodo, data_inicio, data_fim)
        dias_periodo = _dias_do_periodo(periodo, data_inicio, data_fim)
        
        # Adicionar filtro de analista se existir
        if analista_filtro:
            where_clause += " AND analista = ?"
            params.append(analista_filtro)

        # Excluir gerente 'Erica' de todas as estatísticas agregadas
        where_clause_full = f"{where_clause} AND LOWER(COALESCE(analista,'')) <> 'erica'"

        print(f"📊 DEBUG: Query WHERE: {where_clause_full}")
        print(f"📊 DEBUG: Parâmetros: {params}")

        # 1. ESTATÍSTICAS DETALHADAS POR ANALISTA
        query_analistas = f"""
            SELECT 
                COALESCE(analista, '(Sem Analista)') as analista,
                COUNT(*) as total,
                SUM(CASE WHEN data_conclusao IS NOT NULL AND data_conclusao != '' THEN 1 ELSE 0 END) as concluidos,
                SUM(CASE WHEN status_processo = 'aguardando_orientacao' THEN 1 ELSE 0 END) as aguardando_orientacao,
                SUM(CASE WHEN status_processo = 'aguardando_chamado' THEN 1 ELSE 0 END) as aguardando_chamado,
                SUM(CASE WHEN status_processo = 'sobrestado' THEN 1 ELSE 0 END) as sobrestado
            FROM historico_setor 
            WHERE {where_clause_full}
            GROUP BY analista
            ORDER BY total DESC
        """
        
        cur = conn.execute(query_analistas, params)
        analistas_rows = cur.fetchall()
        
        print(f"📊 DEBUG: {len(analistas_rows)} analistas encontrados")
        
        por_analista_detalhado = {}
        
        for row in analistas_rows:
            analista = row[0]
            total = int(row[1] or 0)
            concluidos = int(row[2] or 0)
            aguardando_orientacao = int(row[3] or 0)
            aguardando_chamado = int(row[4] or 0)
            sobrestado = int(row[5] or 0)
            
            em_andamento = total - concluidos
            perc = round((concluidos / total * 100.0), 1) if total else 0.0

            por_analista_detalhado[analista] = {
                'total': total,
                'concluidos': concluidos,
                'em_andamento': em_andamento,
                'aguardando_orientacao': aguardando_orientacao,
                'aguardando_chamado': aguardando_chamado,
                'sobrestado': sobrestado,
                'percentual': perc
            }
        
        # 2. EVOLUÇÃO TEMPORAL
        # CORREÇÃO: Usar a mesma cláusula WHERE
        query_evolucao = f"""
            SELECT 
                date(data_distribuicao) as data,
                COUNT(*) as quantidade
            FROM historico_setor 
            WHERE {where_clause_full}
            GROUP BY date(data_distribuicao)
            ORDER BY data
        """
        
        cur = conn.execute(query_evolucao, params)
        evolucao_rows = cur.fetchall()
        
        evolucao = {}
        for row in evolucao_rows:
            if row[0]:
                evolucao[row[0]] = int(row[1])
        
        print(f"📊 DEBUG: {len(evolucao)} dias de evolução")
        
        # 3. STATUS DOS PROCESSOS
        query_status = f"""
            SELECT 
                CASE 
                    WHEN data_conclusao IS NOT NULL AND data_conclusao != '' THEN 'Concluído'
                    ELSE COALESCE(status_processo, 'Em Andamento')
                END as status,
                COUNT(*) as quantidade
            FROM historico_setor 
            WHERE {where_clause_full}
            GROUP BY status
            ORDER BY quantidade DESC
        """
        
        cur = conn.execute(query_status, params)
        status_rows = cur.fetchall()
        
        status_data = {}
        for row in status_rows:
            status_data[row[0]] = int(row[1])
        
        print(f"📊 DEBUG: {len(status_data)} tipos de status")
        
        conn.close()
        
        # Preparar resposta
        estatisticas = {
            'por_analista_detalhado': por_analista_detalhado,
            'evolucao': evolucao,
            'status': status_data,
            'periodo_aplicado': periodo,
            'total_registros': sum(d['total'] for d in por_analista_detalhado.values())
        }
        
        print(f"✅ DEBUG: Estatísticas geradas - {len(por_analista_detalhado)} analistas, {len(evolucao)} dias, {estatisticas['total_registros']} processos")
        
        return jsonify({
            'success': True,
            'estatisticas': estatisticas,
            'debug': {
                'periodo': periodo,
                'analista_filtro': analista_filtro,
                'where_clause': where_clause,
                'params': params
            }
        })
        
    except Exception as e:
        print(f"❌ DEBUG: Erro nas estatísticas: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'message': str(e),
            'estatisticas': {
                'por_analista': {},
                'por_analista_detalhado': {},
                'evolucao': {},
                'status': {}
            }
        })

# =============================================================================
# API PARA MÉDIA DE DISTRIBUIÇÃO DINÂMICA
# =============================================================================

@app.route('/sar/api/media-distribuicao')
@login_required
@role_required('gerente', 'admin')
def api_media_distribuicao():
    """
    Calcular média de distribuição por analista por dia útil - VERSÃO CORRIGIDA
    Fórmula: Total de processos ÷ (Dias úteis × Número de analistas)
    """
    try:
        conn = get_db()
        
        # 1. Contar processos históricos (base de dados histórica)
        cur = conn.execute('''
            SELECT COUNT(*) 
            FROM historico_setor 
            WHERE data_distribuicao IS NOT NULL 
              AND strftime('%Y', data_distribuicao) = strftime('%Y', 'now')
        ''')
        processos_historicos = cur.fetchone()[0]
        
        # 2. Contar processos novos no sistema (tabela processos)
        cur = conn.execute('''
            SELECT COUNT(*) 
            FROM processos 
            WHERE analista_id IS NOT NULL
              AND strftime('%Y', criado_em) = strftime('%Y', 'now')
        ''')
        processos_novos = cur.fetchone()[0]
        
        # 3. Total de processos (histórico + novos)
        total_processos = processos_historicos + processos_novos
        
        # 4. Número de analistas ativos
        cur = conn.execute('''
            SELECT COUNT(*) 
            FROM usuarios 
            WHERE papel = 'analista' AND ativo = 1
        ''')
        num_analistas = cur.fetchone()[0]
        
        # 5. CALCULAR DIAS ÚTEIS DO ANO ATÉ HOJE
        from datetime import date
        hoje = date.today()
        inicio_ano = date(hoje.year, 1, 1)
        dias_uteis_ano = 0
        
        # Contar apenas dias úteis (segunda a sexta)
        current_date = inicio_ano
        while current_date <= hoje:
            if current_date.weekday() < 5:  # 0-4 = segunda a sexta
                dias_uteis_ano += 1
            # CORREÇÃO: Usar timedelta para incrementar a data corretamente
            current_date += timedelta(days=1)
        
        # 6. CÁLCULO CORRETO: processos ÷ (dias úteis × analistas)
        if dias_uteis_ano > 0 and num_analistas > 0:
            media_correta = round(total_processos / (dias_uteis_ano * num_analistas), 1)
        else:
            media_correta = 0.0
        
        # 7. Para comparação, calcular a média "errada" anterior
        media_errada = round(total_processos / num_analistas, 1) if num_analistas > 0 else 0.0
        
        conn.close()
        
        print(f"✅ MÉDIA CORRIGIDA:")
        print(f"📊 Processos históricos: {processos_historicos}")
        print(f"📊 Processos novos: {processos_novos}")
        print(f"📊 Total processos: {total_processos}")
        print(f"📊 Analistas ativos: {num_analistas}")
        print(f"� Dias úteis 2025: {dias_uteis_ano}")
        print(f"✅ MÉDIA CORRETA: {total_processos} ÷ ({dias_uteis_ano} × {num_analistas}) = {media_correta}")
        print(f"❌ Média anterior (errada): {media_errada}")
        
        return jsonify({
            'success': True,
            'media': media_correta,  # ← AGORA RETORNA A MÉDIA CORRETA!
            'processos_historicos': processos_historicos,
            'processos_novos': processos_novos,
            'total_processos': total_processos,
            'num_analistas': num_analistas,
            'dias_uteis_ano': dias_uteis_ano,
            'formula_correta': f"{total_processos} ÷ ({dias_uteis_ano} × {num_analistas}) = {media_correta}",
            'media_anterior_errada': media_errada,
            'explicacao': f"Média CORRETA: {media_correta} processos por analista por dia útil (considerando {dias_uteis_ano} dias úteis em {hoje.year})",
            'detalhamento': {
                'base_historica': f"Base histórica: {processos_historicos} processos do histórico 2025",
                'processos_sistema': f"Processos sistema: {processos_novos} processos ativos atribuídos",
                'total_computado': f"Total computado: {total_processos} processos",
                'calculo': f"Média = {total_processos} processos ÷ ({dias_uteis_ano} dias úteis × {num_analistas} analistas) = {media_correta}"
            }
        })
        
    except Exception as e:
        print(f"❌ Erro no cálculo da média: {e}")
        return jsonify({
            'success': False,
            'message': str(e),
            'media': 0.0
        })

# =============================================================================
# APIS PARA NOTIFICAÇÕES
# =============================================================================

@app.route('/api/notificacoes/listar', methods=['GET'])
@login_required
def api_listar_notificacoes():
    """Listar notificações do usuário atual."""
    try:
        user = get_current_user()
        conn = get_db()
        
        # Buscar notificações do usuário (últimas 50)
        cur = conn.execute('''
            SELECT n.id, n.tipo, n.titulo, n.mensagem, n.processo_numero, 
                   n.status_anterior, n.status_novo, n.lida, n.criado_em,
                   u.primeiro_nome as origem_nome
            FROM notificacoes n
            LEFT JOIN usuarios u ON n.usuario_origem_id = u.id
            WHERE n.usuario_destino_id = ?
            ORDER BY n.criado_em DESC
            LIMIT 50
        ''', (user['id'],))
        
        notificacoes = []
        nao_lidas = 0
        
        for row in cur.fetchall():
            notif = {
                'id': row[0],
                'tipo': row[1],
                'titulo': row[2],
                'mensagem': row[3],
                'processo_numero': row[4],
                'status_anterior': row[5],
                'status_novo': row[6],
                'lida': bool(row[7]),
                'criado_em': row[8],
                'origem_nome': row[9]
            }
            notificacoes.append(notif)
            
            if not notif['lida']:
                nao_lidas += 1
        
        conn.close()
        
        return jsonify({
            'success': True,
            'notificacoes': notificacoes,
            'nao_lidas': nao_lidas
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/notificacoes/marcar-lida/<int:notif_id>', methods=['POST'])
@login_required
def api_marcar_notificacao_lida(notif_id):
    """Marcar notificação específica como lida."""
    try:
        user = get_current_user()
        conn = get_db()
        
        conn.execute('''
            UPDATE notificacoes 
            SET lida = 1 
            WHERE id = ? AND usuario_destino_id = ?
        ''', (notif_id, user['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/notificacoes/marcar-todas-lidas', methods=['POST'])
@login_required
def api_marcar_todas_notificacoes_lidas():
    """Marcar todas as notificações como lidas."""
    try:
        user = get_current_user()
        conn = get_db()
        
        conn.execute('''
            UPDATE notificacoes 
            SET lida = 1 
            WHERE usuario_destino_id = ? AND lida = 0
        ''', (user['id'],))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/notificacoes/excluir/<int:notif_id>', methods=['DELETE', 'POST'])
@login_required
def api_excluir_notificacao(notif_id):
    """Excluir definitivamente uma notificação do usuário atual."""
    try:
        user = get_current_user()
        conn = get_db()
        try:
            cur = conn.execute(
                'SELECT id FROM notificacoes WHERE id = ? AND usuario_destino_id = ?',
                (notif_id, user['id'])
            )
            if not cur.fetchone():
                return jsonify({'success': False, 'message': 'Notificação não encontrada'}), 404
            conn.execute('DELETE FROM notificacoes WHERE id = ?', (notif_id,))
            conn.commit()
        finally:
            conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Erro ao excluir: {str(e)}'})

# =============================================================================
# APIS PARA CHAT BÁSICO (COMPATIBILIDADE)
# =============================================================================

@app.route('/api/chat/mensagens', methods=['GET'])
@login_required
def api_listar_mensagens_chat():
    """Listar mensagens do chat (últimas 50)."""
    try:
        user = get_current_user()
        conn = get_db()
        
        # Buscar mensagens do chat (últimas 50)
        cur = conn.execute('''
            SELECT id, remetente_id, destinatario_id, tipo, assunto, mensagem, processo_numero, lida, criado_em
            FROM chat_mensagens
            WHERE destinatario_id = ? OR remetente_id = ?
            ORDER BY criado_em DESC
            LIMIT 50
        ''', (user['id'], user['id']))
        
        mensagens = []
        for row in cur.fetchall():
            mensagem = {
                'id': row[0],
                'remetente_id': row[1],
                'destinatario_id': row[2],
                'tipo': row[3],
                'assunto': row[4],
                'mensagem': row[5],
                'processo_numero': row[6],
                'lida': bool(row[7]),
                'criado_em': row[8]
            }
            mensagens.append(mensagem)
        
        # Marcar mensagens como lidas
        conn.execute('''
            UPDATE chat_mensagens 
            SET lida = 1 
            WHERE destinatario_id = ? AND lida = 0
        ''', (user['id'],))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'mensagens': mensagens
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/chat/enviar', methods=['POST'])
@login_required
def api_enviar_mensagem_chat():
    """Enviar mensagem no chat (versão básica)."""
    try:
        data = request.get_json() or {}
        mensagem = (data.get('mensagem') or '').strip()
        assunto = (data.get('assunto') or '').strip()
        
        if not mensagem:
            return jsonify({'success': False, 'message': 'Mensagem é obrigatória'})
        
        user = get_current_user()
        conn = get_db()
        
        # Determinar destinatários baseado no papel
        if user['papel'] in ['gerente', 'admin']:
            # Gerentes enviam para todos os analistas
            cur = conn.execute('''
                SELECT id FROM usuarios 
                WHERE papel = 'analista' AND ativo = 1
            ''')
            destinatarios = [row[0] for row in cur.fetchall()]
        else:
            # Analistas enviam para gerentes
            cur = conn.execute('''
                SELECT id FROM usuarios 
                WHERE papel IN ('gerente', 'admin') AND ativo = 1
            ''')
            destinatarios = [row[0] for row in cur.fetchall()]
        
        # Enviar para cada destinatário
        for dest_id in destinatarios:
            conn.execute('''
                INSERT INTO chat_mensagens 
                (remetente_id, destinatario_id, tipo, assunto, mensagem)
                VALUES (?, ?, 'direto', ?, ?)
            ''', (user['id'], dest_id, assunto, mensagem))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': f'Mensagem enviada para {len(destinatarios)} destinatário(s)'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# =============================================================================
# INICIALIZAÇÃO DA APLICAÇÃO
# =============================================================================

if __name__ == '__main__':
    print("🚀 Iniciando Sistema SAR...")
    print("=" * 50)
    verificar_e_migrar_banco()
    criar_usuarios_padrao()
    corrigir_nomes_duplicados()
    migrar_colunas_historico()
    print("=" * 50)
    print("✅ Sistema SAR inicializado com sucesso!")
    print("🌐 Acesse: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)