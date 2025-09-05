# fix_users.py
from app import app, db, Usuario

USERS = [
    ("Erica", "gerente", "1234"),
    ("Bruno", "analista", "1234"),
    ("Vanessa", "analista", "1234"),
    ("Alessandro", "analista", "1234"),
    ("Carmen", "analista", "1234"),
    ("Zenilda", "analista", "1234"),
]

def upsert(nome: str, papel: str, senha: str):
    u = Usuario.query.filter(Usuario.primeiro_nome.ilike(nome)).first()
    if not u:
        u = Usuario(primeiro_nome=nome, papel=papel, ativo=True)
        u.set_senha(senha)
        db.session.add(u)
        print(f"✓ Criado: {nome} ({papel})")
    else:
        u.papel = papel
        u.ativo = True
        u.set_senha(senha)
        print(f"✓ Atualizado: {nome} → papel={papel}, senha resetada, ativo=True")
    db.session.commit()

def disable(nome: str):
    u = Usuario.query.filter(Usuario.primeiro_nome.ilike(nome)).first()
    if u:
        u.ativo = False
        db.session.commit()
        print(f"• Desativado: {nome}")

if __name__ == "__main__":
    with app.app_context():
        for nome, papel, senha in USERS:
            upsert(nome, papel, senha)
        # opcional: desativa usuário antigo "Chefe"
        disable("Chefe")

        print("\n--- Usuários no banco ---")
        for u in Usuario.query.order_by(Usuario.primeiro_nome).all():
            print(f"{u.id:>2}  {u.primeiro_nome:10}  papel={u.papel:8}  ativo={u.ativo}")
