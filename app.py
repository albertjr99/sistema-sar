from __future__ import annotations

import io
import json
import os
from datetime import datetime
from functools import wraps

import openpyxl
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.orm import validates
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------
# Configuração básica
# ---------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "troque-esta-chave")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///sar.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
EXPORT_DIR = os.path.join(BASE_DIR, "export")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

socketio = SocketIO(app, async_mode="eventlet")
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------
class Usuario(db.Model, UserMixin):
    __tablename__ = "usuarios"

    id = db.Column(db.Integer, primary_key=True)
    primeiro_nome = db.Column(db.String(80), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    papel = db.Column(db.String(20), nullable=False, default="analista")  # analista|gerente|admin
    ativo = db.Column(db.Boolean, default=True)

    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_senha(self, senha: str) -> None:
        self.senha_hash = generate_password_hash(senha)

    def check_senha(self, senha: str) -> bool:
        return check_password_hash(self.senha_hash, senha)


class Processo(db.Model):
    __tablename__ = "processos"

    id = db.Column(db.Integer, primary_key=True)
    numero = db.Column(db.String(100), unique=True, nullable=False)
    titulo = db.Column(db.String(200), nullable=False)
    descricao = db.Column(db.Text, default="")
    prioridade = db.Column(db.String(10), default="media")  # baixa|media|alta|critica
    status = db.Column(db.String(20), default="novo")       # novo|em_analise|aguardando|concluido|arquivado
    setor = db.Column(db.String(50), default="SAR")

    gerente_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"))
    analista_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"), nullable=True)

    observacoes = db.Column(db.Text, default="")
    data_atribuicao = db.Column(db.DateTime, nullable=True)
    data_conclusao = db.Column(db.DateTime, nullable=True)

    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    gerente = db.relationship("Usuario", foreign_keys=[gerente_id])
    analista = db.relationship("Usuario", foreign_keys=[analista_id])

    @validates("prioridade", "status")
    def validate_enum(self, key, value):
        enums = {
            "prioridade": {"baixa", "media", "alta", "critica"},
            "status": {"novo", "em_analise", "aguardando", "concluido", "arquivado"},
        }
        if value not in enums[key]:
            raise ValueError(f"{key} inválido: {value}")
        return value


class HistoricoPlanilha(db.Model):
    __tablename__ = "historico_planilha"

    id = db.Column(db.Integer, primary_key=True)
    origem = db.Column(db.String(20), default="sistema")  # importado|sistema
    dados = db.Column(db.Text, nullable=False)            # JSON com campos originais
    chave_processo = db.Column(db.String(120), index=True)
    analista_primeiro_nome = db.Column(db.String(80), index=True)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


class Auditoria(db.Model):
    __tablename__ = "auditoria"

    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey("usuarios.id"))
    entidade = db.Column(db.String(50))
    entidade_id = db.Column(db.Integer)
    acao = db.Column(db.String(30))
    dif_json = db.Column(db.Text)  # JSON com antes/depois
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


class DistribuicaoHistorica(db.Model):
    __tablename__ = "distribuicao_historica"

    id = db.Column(db.Integer, primary_key=True)
    ano = db.Column(db.Integer, index=True)
    mes = db.Column(db.Integer, index=True)  # 1..12
    sheet = db.Column(db.String(20))         # ex.: 2025-Jul

    ordem_geral = db.Column(db.Integer)
    analista = db.Column(db.String(80), index=True)
    numero = db.Column(db.String(50), index=True)
    data = db.Column(db.Date)
    interessado = db.Column(db.String(200))
    assunto = db.Column(db.String(100), index=True)
    setor_origem = db.Column(db.String(100), index=True)
    tipo_processo = db.Column(db.String(20), index=True)  # DIGITAL|FÍSICO|HÍBRIDO|JUDICIAL
    data_distribuicao = db.Column(db.DateTime)
    data_conclusao = db.Column(db.DateTime)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------------------------------------------------------------
# Utilidades e segurança
# ---------------------------------------------------------------------
@login_manager.user_loader
def load_user(user_id: str):
    return Usuario.query.get(int(user_id))


def role_required(*papeis: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.papel not in papeis:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def registrar_auditoria(entidade: str, entidade_id: int, acao: str, dif: dict) -> None:
    reg = Auditoria(
        usuario_id=current_user.id if current_user.is_authenticated else None,
        entidade=entidade,
        entidade_id=entidade_id,
        acao=acao,
        dif_json=json.dumps(dif, ensure_ascii=False),
    )
    db.session.add(reg)


def emitir_stats() -> None:
    by_status = (
        db.session.query(Processo.status, func.count(Processo.id))
        .group_by(Processo.status)
        .all()
    )
    stats_all = {k: v for k, v in by_status}

    por_analista = (
        db.session.query(Usuario.primeiro_nome, func.count(Processo.id))
        .join(Usuario, Usuario.id == Processo.analista_id)
        .group_by(Usuario.primeiro_nome)
        .all()
    )
    stats_users = {k: v for k, v in por_analista}

    # emitir para todos (sem broadcast=True nas versões novas)
    socketio.emit("stats_update", {"all": stats_all, "users": stats_users})

# ---------------------------------------------------------------------
# Autenticação
# ---------------------------------------------------------------------
@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = (request.form.get("primeiro_nome") or "").strip()
        senha = request.form.get("senha") or ""
        u = Usuario.query.filter(func.lower(Usuario.primeiro_nome) == func.lower(nome)).first()
        if u and u.check_senha(senha) and u.ativo:
            login_user(u)
            if u.papel in ("gerente", "admin"):
                return redirect(url_for("painel_gerencia"))
            return redirect(url_for("painel_analista"))
        flash("Credenciais inválidas ou usuário inativo.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))

# ---------------------------------------------------------------------
# Painel do Analista
# ---------------------------------------------------------------------
@app.route("/analista")
@login_required
@role_required("analista", "gerente", "admin")
def painel_analista():
    analista_id = (
        current_user.id
        if current_user.papel == "analista"
        else request.args.get("analista_id", type=int) or current_user.id
    )
    status = request.args.get("status")
    q = Processo.query.filter_by(analista_id=analista_id)
    if status:
        q = q.filter_by(status=status)
    processos = q.order_by(Processo.prioridade.desc(), Processo.atualizado_em.desc()).all()

    cont = (
        db.session.query(Processo.status, func.count(Processo.id))
        .filter_by(analista_id=analista_id)
        .group_by(Processo.status)
        .all()
    )
    contagem = {k: v for k, v in cont}
    return render_template("analista.html", processos=processos, contagem=contagem)


@app.route("/analista/processo/<int:pid>/salvar", methods=["POST"])
@login_required
@role_required("analista", "gerente", "admin")
def salvar_processo_analista(pid: int):
    p = Processo.query.get_or_404(pid)
    if current_user.papel == "analista" and p.analista_id != current_user.id:
        abort(403)

    antes = {"status": p.status, "observacoes": p.observacoes}

    novo_status = request.form.get("status")
    obs = request.form.get("observacoes")

    if novo_status:
        p.status = novo_status
        if p.status == "concluido" and not p.data_conclusao:
            p.data_conclusao = datetime.utcnow()
    if obs is not None:
        p.observacoes = obs

    db.session.commit()
    registrar_auditoria(
        "processo", p.id, "editar",
        {"antes": antes, "depois": {"status": p.status, "observacoes": p.observacoes}}
    )
    emitir_stats()
    return jsonify(ok=True)

# ---------------------------------------------------------------------
# Painel da Gerência
# ---------------------------------------------------------------------
@app.route("/gerencia")
@login_required
@role_required("gerente", "admin")
def painel_gerencia():
    analista = request.args.get("analista")
    status = request.args.get("status")

    processos = Processo.query
    if analista:
        u = Usuario.query.filter(func.lower(Usuario.primeiro_nome) == func.lower(analista)).first()
        if u:
            processos = processos.filter_by(analista_id=u.id)
    if status:
        processos = processos.filter_by(status=status)

    processos = processos.order_by(Processo.atualizado_em.desc()).all()
    analistas = (
        Usuario.query.filter(Usuario.papel == "analista", Usuario.ativo.is_(True))
        .order_by(Usuario.primeiro_nome.asc()).all()
    )
    by_status = db.session.query(Processo.status, func.count(Processo.id)).group_by(Processo.status).all()
    stats = {k: v for k, v in by_status}

    return render_template("gerencia.html", processos=processos, analistas=analistas, stats=stats)


@app.route("/gerencia/processo/novo", methods=["POST"])
@login_required
@role_required("gerente", "admin")
def criar_processo():
    numero = (request.form.get("numero") or "").strip()
    titulo = (request.form.get("titulo") or "").strip()
    prioridade = request.form.get("prioridade", "media")
    analista_primeiro_nome = request.form.get("analista")

    if not numero or not titulo:
        return jsonify(ok=False, erro="Número e Título são obrigatórios."), 400

    if Processo.query.filter_by(numero=numero).first():
        return jsonify(ok=False, erro="Já existe processo com este número."), 400

    analista = None
    if analista_primeiro_nome:
        analista = Usuario.query.filter(func.lower(Usuario.primeiro_nome) == func.lower(analista_primeiro_nome)).first()

    p = Processo(
        numero=numero,
        titulo=titulo,
        prioridade=prioridade,
        gerente_id=current_user.id,
        analista_id=analista.id if analista else None,
        data_atribuicao=datetime.utcnow() if analista else None,
    )
    db.session.add(p)
    db.session.flush()

    dados = {
        "numero": numero,
        "titulo": titulo,
        "prioridade": prioridade,
        "analista": analista.primeiro_nome if analista else "",
        "gerente": current_user.primeiro_nome,
        "status": "novo",
        "data_atribuicao": datetime.utcnow().isoformat(timespec="seconds") if analista else "",
    }
    hp = HistoricoPlanilha(
        origem="sistema",
        dados=json.dumps(dados, ensure_ascii=False),
        chave_processo=numero,
        analista_primeiro_nome=dados["analista"],
    )
    db.session.add(hp)

    db.session.commit()
    registrar_auditoria("processo", p.id, "criar", {"novo": dados})
    emitir_stats()
    return jsonify(ok=True, id=p.id)


@app.route("/gerencia/processo/<int:pid>/atribuir", methods=["POST"])
@login_required
@role_required("gerente", "admin")
def atribuir_processo(pid: int):
    p = Processo.query.get_or_404(pid)
    analista_primeiro_nome = request.form.get("analista")
    analista = Usuario.query.filter(func.lower(Usuario.primeiro_nome) == func.lower(analista_primeiro_nome)).first()
    if not analista:
        return jsonify(ok=False, erro="Analista não encontrado."), 404

    antes = {"analista_id": p.analista_id}
    p.analista_id = analista.id
    p.data_atribuicao = datetime.utcnow()

    ultimo = (
        HistoricoPlanilha.query.filter_by(chave_processo=p.numero).order_by(HistoricoPlanilha.id.desc()).first()
    )
    dados = json.loads(ultimo.dados) if ultimo else {}
    dados.update({
        "analista": analista.primeiro_nome,
        "status": p.status,
        "data_atribuicao": p.data_atribuicao.isoformat(timespec="seconds"),
    })
    hp = HistoricoPlanilha(
        origem="sistema",
        dados=json.dumps(dados, ensure_ascii=False),
        chave_processo=p.numero,
        analista_primeiro_nome=analista.primeiro_nome,
    )
    db.session.add(hp)

    db.session.commit()
    registrar_auditoria("processo", p.id, "atribuir", {"antes": antes, "depois": {"analista_id": p.analista_id}})
    emitir_stats()
    return jsonify(ok=True)

# ---------------------------------------------------------------------
# Histórico genérico (import/export)
# ---------------------------------------------------------------------
@app.route("/gerencia/historico")
@login_required
@role_required("gerente", "admin")
def historico_view():
    analista = request.args.get("analista")
    chave = request.args.get("chave")

    q = HistoricoPlanilha.query
    if analista:
        q = q.filter(func.lower(HistoricoPlanilha.analista_primeiro_nome) == func.lower(analista))
    if chave:
        q = q.filter(HistoricoPlanilha.chave_processo.ilike(f"%{chave}%"))

    registros = q.order_by(HistoricoPlanilha.id.desc()).limit(500).all()

    linhas = []
    for r in registros:
        try:
            linhas.append(json.loads(r.dados))
        except Exception:
            linhas.append({"dados": r.dados})

    return render_template("historico.html", linhas=linhas)


@app.route("/gerencia/historico/importar", methods=["POST"])
@login_required
@role_required("gerente", "admin")
def historico_importar():
    f = request.files.get("arquivo")
    if not f:
        flash("Selecione um arquivo .xlsx", "warning")
        return redirect(url_for("historico_view"))

    wb = openpyxl.load_workbook(f)
    ws = wb.active
    headers = [c.value for c in next(ws.iter_rows(min_row=1, max_row=1))]
    for row in ws.iter_rows(min_row=2, values_only=True):
        dados = {str(headers[i]): (row[i] if i < len(row) else None) for i in range(len(headers))}
        chave = str(dados.get("numero") or dados.get("Número") or dados.get("processo") or "")
        analista = str(dados.get("analista") or dados.get("Analista") or "")
        reg = HistoricoPlanilha(
            origem="importado",
            dados=json.dumps(dados, ensure_ascii=False, default=str),
            chave_processo=chave,
            analista_primeiro_nome=analista,
        )
        db.session.add(reg)

    db.session.commit()
    flash("Planilha importada com sucesso.", "success")
    return redirect(url_for("historico_view"))


@app.route("/gerencia/historico/exportar")
@login_required
@role_required("gerente", "admin")
def historico_exportar():
    q = HistoricoPlanilha.query.order_by(HistoricoPlanilha.id.asc()).all()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Historico"

    chaves = []
    for r in q[:1000]:
        d = json.loads(r.dados)
        for k in d.keys():
            if k not in chaves:
                chaves.append(k)
    if "numero" not in chaves:
        chaves.insert(0, "numero")

    ws.append(chaves)
    for r in q:
        d = json.loads(r.dados)
        ws.append([d.get(k, "") for k in chaves])

    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    nome = f"historico_sar_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        bio,
        as_attachment=True,
        download_name=nome,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# ---------------------------------------------------------------------
# Distribuição Histórica (espelho abas 2021..2025)
# ---------------------------------------------------------------------
@app.route("/gerencia/distribuicao")
@login_required
@role_required("gerente", "admin")
def distribuicao_historica_view():
    ano = request.args.get("ano", type=int)
    mes = request.args.get("mes", type=int)
    analista = request.args.get("analista")

    q = DistribuicaoHistorica.query
    if ano:
        q = q.filter_by(ano=ano)
    if mes:
        q = q.filter_by(mes=mes)
    if analista:
        q = q.filter(func.lower(DistribuicaoHistorica.analista) == func.lower(analista))

    linhas = q.order_by(
        DistribuicaoHistorica.ano.desc(),
        DistribuicaoHistorica.mes.desc(),
        DistribuicaoHistorica.ordem_geral.asc()
    ).limit(2000).all()
    return render_template("distribuicao.html", linhas=linhas)


@app.route("/gerencia/distribuicao/exportar")
@login_required
@role_required("gerente", "admin")
def distribuicao_exportar():
    ano = request.args.get("ano", type=int)
    mes = request.args.get("mes", type=int)
    analista = request.args.get("analista")

    q = DistribuicaoHistorica.query
    if ano:
        q = q.filter_by(ano=ano)
    if mes:
        q = q.filter_by(mes=mes)
    if analista:
        q = q.filter(func.lower(DistribuicaoHistorica.analista) == func.lower(analista))

    regs = q.order_by(
        DistribuicaoHistorica.ano,
        DistribuicaoHistorica.mes,
        DistribuicaoHistorica.ordem_geral
    ).all()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Distribuicao"

    head = [
        "ORDEM GERAL", "ANALISTA", "NÚMERO", "DATA", "INTERESSADO",
        "ASSUNTO", "SETOR ORIGEM", "TIPO PROCESSO", "DATA DISTRIBUIÇÃO", "DATA CONCLUSÃO",
    ]
    ws.append(head)

    for r in regs:
        ws.append([
            r.ordem_geral,
            r.analista,
            r.numero,
            r.data.strftime("%d/%m/%Y") if r.data else "",
            r.interessado,
            r.assunto,
            r.setor_origem,
            r.tipo_processo,
            r.data_distribuicao.strftime("%d/%m/%Y") if r.data_distribuicao else "",
            r.data_conclusao.strftime("%d/%m/%Y") if r.data_conclusao else "",
        ])

    bio = io.BytesIO()
    wb.save(bio)
    bio.seek(0)
    nome = f"distribuicao_{ano or 'todos'}_{mes or ''}.xlsx"
    return send_file(
        bio,
        as_attachment=True,
        download_name=nome,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

# ---------------------------------------------------------------------
# APIs de estatística (para gráficos futuros)
# ---------------------------------------------------------------------
@app.route("/api/stats/geral")
@login_required
def api_stats_geral():
    by_status = db.session.query(Processo.status, func.count(Processo.id)).group_by(Processo.status).all()
    por_analista = (
        db.session.query(Usuario.primeiro_nome, func.count(Processo.id))
        .join(Usuario, Usuario.id == Processo.analista_id)
        .group_by(Usuario.primeiro_nome)
        .all()
    )
    return jsonify(
        por_status={k: v for k, v in by_status},
        por_analista={k: v for k, v in por_analista}
    )

# ---------------------------------------------------------------------
# Erros
# ---------------------------------------------------------------------
@app.errorhandler(403)
def _403(e):
    return render_template("error.html", codigo=403, mensagem="Acesso negado"), 403

@app.errorhandler(404)
def _404(e):
    return render_template("error.html", codigo=404, mensagem="Não encontrado"), 404

# ---------------------------------------------------------------------
# Socket.IO
# ---------------------------------------------------------------------
@socketio.on("connect")
def on_connect():
    emit("connected", {"ok": True})

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
if __name__ == "__main__":
    socketio.run(app, debug=True)
