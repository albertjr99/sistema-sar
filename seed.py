from app import app, db, Usuario

USERS = [
    ("Erica", "gerente", "1234"),
    ("Bruno", "analista", "1234"),
    ("Vanessa", "analista", "1234"),
    ("Alessandro", "analista", "1234"),
    ("Carmen", "analista", "1234"),
    ("Zenilda", "analista", "1234"),
]

def upsert_user(nome: str, papel: str, senha: str):
    u = Usuario.query.filter(Usuario.primeiro_nome.ilike(nome)).first()
    if not u:
        u = Usuario(primeiro_nome=nome, papel=papel, ativo=True)
        u.set_senha(senha)
        db.session.add(u)
        print(f"✓ Criado: {nome} ({papel})")
    else:
        u.papel = papel
        u.ativo = True
        u.set_senha(senha)  # reseta senha
        print(f"✓ Atualizado: {nome} → papel={papel}, senha=1234, ativo=True")
    db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        for nome, papel, senha in USERS:
            upsert_user(nome, papel, senha)
