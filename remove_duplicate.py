import os

# Remover arquivo duplicado
arquivo_duplicado = r'c:\Users\albert.junior\OneDrive\sar-sistema\templates\central_estatisticas_fixed.html'
if os.path.exists(arquivo_duplicado):
    os.remove(arquivo_duplicado)
    print(f"✅ Arquivo removido: {arquivo_duplicado}")
else:
    print(f"ℹ️ Arquivo não encontrado: {arquivo_duplicado}")