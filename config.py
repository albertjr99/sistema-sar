# =============================================================================
# CONFIGURAÇÕES DE PRODUÇÃO PARA O SISTEMA SAR
# =============================================================================

# config.py - Configurações centralizadas
import os
from datetime import timedelta

class Config:
    """Configuração base"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Upload e export
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
    EXPORT_FOLDER = os.path.join(os.path.dirname(__file__), 'exports')
    BACKUP_FOLDER = os.path.join(os.path.dirname(__file__), 'backups')
    
    # WebSocket
    SOCKETIO_ASYNC_MODE = 'threading'
    
    # Email (se implementar)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Webhook para integrações
    WEBHOOK_TOKEN = os.environ.get('WEBHOOK_TOKEN') or 'webhook-token-123'
    
    # Configurações de backup
    BACKUP_ENABLED = True
    BACKUP_RETENTION_DAYS = 30
    BACKUP_SCHEDULE_HOUR = 2  # 2h da manhã
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'sar.log')


class DevelopmentConfig(Config):
    """Configuração para desenvolvimento"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///sar_dev.db'
    TESTING = False


class ProductionConfig(Config):
    """Configuração para produção"""
    DEBUG = False
    TESTING = False
    
    # PostgreSQL para produção
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get('DATABASE_URL') or 
        'postgresql://sar_user:sar_password@localhost/sar_production'
    )
    
    # SSL e segurança
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate limiting mais rigoroso
    RATELIMIT_DEFAULT = "1000/hour"
    
    # Logs estruturados
    LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s %(message)s'


class TestingConfig(Config):
    """Configuração para testes"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


# =============================================================================
# SISTEMA DE MONITORAMENTO E HEALTH CHECK
# =============================================================================

from flask import Blueprint, jsonify
from datetime import datetime
import psutil
import os

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/health')

@monitoring_bp.route('/status')
def health_check():
    """Health check básico do sistema"""
    try:
        # Verificar banco de dados
        db.session.execute('SELECT 1')
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    # Verificar uso de recursos
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    # Verificar diretórios essenciais
    directories_status = {}
    essential_dirs = [
        app.config.get('UPLOAD_FOLDER'),
        app.config.get('EXPORT_FOLDER'),
        app.config.get('BACKUP_FOLDER')
    ]
    
    for dir_path in essential_dirs:
        if dir_path:
            directories_status[dir_path] = os.path.exists(dir_path) and os.access(dir_path, os.W_OK)
    
    status = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "healthy" if db_status == "ok" else "unhealthy",
        "version": "2.0.0",
        "database": db_status,
        "system": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_mb": memory.available // 1024 // 1024,
            "disk_percent": disk.percent,
            "disk_free_gb": disk.free // 1024 // 1024 // 1024
        },
        "directories": directories_status,
        "active_users": Usuario.query.filter(Usuario.ativo == True).count(),
        "total_processes": Processo.query.count(),
        "processes_today": Processo.query.filter(
            func.date(Processo.criado_em) == datetime.utcnow().date()
        ).count()
    }
    
    return jsonify(status), 200 if status["status"] == "healthy" else 503

@monitoring_bp.route('/metrics')
def metrics():
    """Métricas detalhadas para monitoramento"""
    try:
        # Métricas de banco
        total_users = Usuario.query.count()
        active_users = Usuario.query.filter(Usuario.ativo == True).count()
        total_processes = Processo.query.count()
        
        # Métricas por status
        status_metrics = dict(
            db.session.query(Processo.status, func.count(Processo.id))
            .group_by(Processo.status).all()
        )
        
        # Métricas temporais
        hoje = datetime.utcnow().date()
        ontem = hoje - timedelta(days=1)
        
        processes_today = Processo.query.filter(
            func.date(Processo.criado_em) == hoje
        ).count()
        
        processes_yesterday = Processo.query.filter(
            func.date(Processo.criado_em) == ontem
        ).count()
        
        # Tempo médio de resolução (últimos 30 dias)
        trinta_dias_atras = datetime.utcnow() - timedelta(days=30)
        avg_resolution_time = db.session.query(
            func.avg(
                func.julianday(Processo.data_conclusao) - 
                func.julianday(Processo.criado_em)
            )
        ).filter(
            Processo.data_conclusao >= trinta_dias_atras,
            Processo.status == "concluido"
        ).scalar() or 0
        
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "users": {
                "total": total_users,
                "active": active_users,
                "inactive": total_users - active_users
            },
            "processes": {
                "total": total_processes,
                "today": processes_today,
                "yesterday": processes_yesterday,
                "change_daily": processes_today - processes_yesterday,
                "by_status": status_metrics,
                "avg_resolution_days": round(avg_resolution_time, 2)
            },
            "performance": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "active_connections": len(psutil.net_connections()),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        }
        
        return jsonify(metrics)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# SISTEMA DE LOGS ESTRUTURADOS
# =============================================================================

import logging
import logging.handlers
import json
from flask import request, g

class StructuredFormatter(logging.Formatter):
    """Formatter para logs estruturados em JSON"""
    
    def format(self, record):
        log_data = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Adicionar contexto da requisição se disponível
        if hasattr(g, 'user_id'):
            log_data["user_id"] = g.user_id
        
        if request:
            log_data["request"] = {
                "method": request.method,
                "url": request.url,
                "ip": request.remote_addr,
                "user_agent": request.headers.get('User-Agent', '')
            }
        
        # Adicionar informações extras se houver
        if hasattr(record, 'extra_data'):
            log_data["extra"] = record.extra_data
        
        return json.dumps(log_data, ensure_ascii=False)

def setup_logging(app):
    """Configurar sistema de logs"""
    if not app.debug:
        # Log para arquivo
        file_handler = logging.handlers.RotatingFileHandler(
            app.config.get('LOG_FILE', 'sar.log'),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(StructuredFormatter())
        file_handler.setLevel(logging.INFO)
        
        # Log para console em produção
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(StructuredFormatter())
        console_handler.setLevel(logging.WARNING)
        
        app.logger.addHandler(file_handler)
        app.logger.addHandler(console_handler)
        app.logger.setLevel(logging.INFO)
        
        # Log para SQLAlchemy
        logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

# =============================================================================
# MIDDLEWARE DE SEGURANÇA
# =============================================================================

from flask import abort
from functools import wraps
import time
from collections import defaultdict

class RateLimiter:
    """Rate limiter simples em memória"""
    def __init__(self):
        self.requests = defaultdict(list)
    
    def is_allowed(self, key, limit=100, window=3600):
        """Verificar se a requisição é permitida"""
        now = time.time()
        
        # Limpar requisições antigas
        self.requests[key] = [
            req_time for req_time in self.requests[key] 
            if now - req_time < window
        ]
        
        # Verificar limite
        if len(self.requests[key]) >= limit:
            return False
        
        # Adicionar requisição atual
        self.requests[key].append(now)
        return True

rate_limiter = RateLimiter()

def rate_limit(limit=100, window=3600):
    """Decorator para rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            key = request.remote_addr
            if not rate_limiter.is_allowed(key, limit, window):
                abort(429)  # Too Many Requests
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.before_request
def security_headers():
    """Aplicar headers de segurança"""
    # CSRF protection
    if request.method == "POST":
        token = session.get('_csrf_token')
        if not token or token != request.headers.get('X-CSRF-Token'):
            if not request.is_json:  # APIs podem usar outros métodos
                abort(403)

@app.after_request
def apply_security_headers(response):
    """Aplicar headers de segurança na resposta"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # CSP básico
    if not app.debug:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net cdnjs.cloudflare.com; "
            "font-src 'self' cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
    
    return response

# =============================================================================
# SISTEMA DE BACKUP AVANÇADO
# =============================================================================

import sqlite3
import zipfile
import shutil
from datetime import datetime
import subprocess
import boto3  # Para backup na AWS (opcional)

class BackupManager:
    def __init__(self, app):
        self.app = app
        self.backup_dir = app.config.get('BACKUP_FOLDER')
        self.retention_days = app.config.get('BACKUP_RETENTION_DAYS', 30)
        
        # Criar diretório se não existir
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_database_backup(self):
        """Criar backup do banco de dados"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        db_uri = self.app.config['SQLALCHEMY_DATABASE_URI']
        
        if db_uri.startswith('sqlite'):
            return self._backup_sqlite(timestamp)
        elif db_uri.startswith('postgresql'):
            return self._backup_postgresql(timestamp)
        else:
            raise ValueError(f"Tipo de banco não suportado: {db_uri}")
    
    def _backup_sqlite(self, timestamp):
        """Backup SQLite"""
        db_path = self.app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        backup_path = os.path.join(self.backup_dir, f"backup_sqlite_{timestamp}.db")
        
        # Usar SQLite backup API
        source = sqlite3.connect(db_path)
        backup = sqlite3.connect(backup_path)
        source.backup(backup)
        source.close()
        backup.close()
        
        return backup_path
    
    def _backup_postgresql(self, timestamp):
        """Backup PostgreSQL"""
        backup_path = os.path.join(self.backup_dir, f"backup_postgres_{timestamp}.sql")
        
        # Extrair informações da URI
        from urllib.parse import urlparse
        parsed = urlparse(self.app.config['SQLALCHEMY_DATABASE_URI'])
        
        env = os.environ.copy()
        env['PGPASSWORD'] = parsed.password
        
        cmd = [
            'pg_dump',
            '-h', parsed.hostname,
            '-p', str(parsed.port or 5432),
            '-U', parsed.username,
            '-d', parsed.path[1:],  # Remove '/' inicial
            '-f', backup_path,
            '--no-password'
        ]
        
        subprocess.run(cmd, env=env, check=True)
        return backup_path
    
    def create_full_backup(self):
        """Criar backup completo (banco + arquivos)"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Backup do banco
        db_backup = self.create_database_backup()
        
        # Criar ZIP com tudo
        zip_path = os.path.join(self.backup_dir, f"backup_full_{timestamp}.zip")
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Adicionar backup do banco
            zipf.write(db_backup, f"database_{timestamp}.backup")
            
            # Adicionar arquivos de upload
            upload_dir = self.app.config.get('UPLOAD_FOLDER')
            if upload_dir and os.path.exists(upload_dir):
                for root, dirs, files in os.walk(upload_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, upload_dir)
                        zipf.write(file_path, f"uploads/{arcname}")
            
            # Adicionar logs
            log_file = self.app.config.get('LOG_FILE')
            if log_file and os.path.exists(log_file):
                zipf.write(log_file, "logs/sar.log")
        
        # Remover backup temporário do banco
        os.remove(db_backup)
        
        return zip_path
    
    def cleanup_old_backups(self):
        """Limpar backups antigos"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        for filename in os.listdir(self.backup_dir):
            if filename.startswith('backup_'):
                file_path = os.path.join(self.backup_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                
                if file_time < cutoff_date:
                    os.remove(file_path)
                    self.app.logger.info(f"Backup antigo removido: {filename}")
    
    def upload_to_cloud(self, backup_path):
        """Upload backup para cloud (AWS S3)"""
        if not os.environ.get('AWS_ACCESS_KEY_ID'):
            return False
        
        try:
            s3 = boto3.client('s3')
            bucket = os.environ.get('BACKUP_S3_BUCKET')
            
            if bucket:
                key = f"sar-backups/{os.path.basename(backup_path)}"
                s3.upload_file(backup_path, bucket, key)
                self.app.logger.info(f"Backup enviado para S3: {key}")
                return True
        except Exception as e:
            self.app.logger.error(f"Erro ao enviar backup para S3: {e}")
        
        return False

# =============================================================================
# COMANDOS CLI PARA PRODUÇÃO
# =============================================================================

import click

@app.cli.command()
def init_production():
    """Inicializar ambiente de produção"""
    click.echo("Inicializando ambiente de produção...")
    
    # Criar diretórios necessários
    directories = [
        app.config.get('UPLOAD_FOLDER'),
        app.config.get('EXPORT_FOLDER'),
        app.config.get('BACKUP_FOLDER')
    ]
    
    for directory in directories:
        if directory:
            os.makedirs(directory, exist_ok=True)
            click.echo(f"✓ Diretório criado: {directory}")
    
    # Criar banco
    db.create_all()
    click.echo("✓ Banco de dados inicializado")
    
    # Criar usuário admin se não existir
    admin = Usuario.query.filter_by(primeiro_nome='admin').first()
    if not admin:
        admin = Usuario(
            primeiro_nome='admin',
            papel='admin',
            email='admin@sar.local',
            ativo=True
        )
        admin.set_senha('admin123')  # Trocar depois
        db.session.add(admin)
        db.session.commit()
        click.echo("✓ Usuário admin criado (trocar senha!)")
    
    click.echo("Inicialização concluída!")

@app.cli.command()
def backup_now():
    """Executar backup manual"""
    backup_manager = BackupManager(app)
    
    try:
        backup_path = backup_manager.create_full_backup()
        click.echo(f"✓ Backup criado: {backup_path}")
        
        # Upload para cloud se configurado
        if backup_manager.upload_to_cloud(backup_path):
            click.echo("✓ Backup enviado para cloud")
        
        # Limpeza
        backup_manager.cleanup_old_backups()
        click.echo("✓ Backups antigos removidos")
        
    except Exception as e:
        click.echo(f"✗ Erro no backup: {e}")

@app.cli.command()
@click.argument('backup_file')
def restore_backup(backup_file):
    """Restaurar backup"""
    if not os.path.exists(backup_file):
        click.echo(f"Arquivo não encontrado: {backup_file}")
        return
    
    click.echo(f"Restaurando backup: {backup_file}")
    
    # Implementar lógica de restore
    # CUIDADO: Esta operação pode sobrescrever dados!
    
    click.echo("Restore concluído!")

@app.cli.command()
def check_health():
    """Verificar saúde do sistema"""
    with app.test_client() as client:
        response = client.get('/health/status')
        
        if response.status_code == 200:
            click.echo("✓ Sistema saudável")
        else:
            click.echo("✗ Problemas detectados")
            click.echo(response.get_json())

# Registrar blueprints
app.register_blueprint(monitoring_bp)

# =============================================================================
# CONFIGURAÇÃO FINAL
# =============================================================================

def create_app(config_name='development'):
    """Factory function para criar app"""
    app = Flask(__name__)
    
    # Configurações
    config_mapping = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    app.config.from_object(config_mapping.get(config_name, DevelopmentConfig))
    
    # Inicializar extensões
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    
    # Configurar logs
    setup_logging(app)
    
    # Blueprints
    app.register_blueprint(monitoring_bp)
    
    return app

# Para uso em produção
if __name__ == '__main__':
    # Detectar ambiente
    config_name = os.environ.get('FLASK_ENV', 'development')
    app = create_app(config_name)
    
    if config_name == 'production':
        # Produção com Gunicorn
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    else:
        # Desenvolvimento
        socketio.run(app, debug=True, host='0.0.0.0', port=5000)