#!/usr/bin/env python3
"""
Script para limpeza de dados de simulação do Sistema SAR
Execute este script para remover dados fictícios da base de dados.
"""

import os
import sys
import sqlite3
from datetime import datetime
import csv

# Adicionar o diretório do projeto ao path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def get_db():
    """Conectar com a base de dados"""
    return sqlite3.connect('sar.db')

def limpar_dados_simulacao():
    """Limpar dados de simulação da base"""
    conn = get_db()
    try:
        print("🧹 Removendo dados de simulação da base...")
        
        # Contar antes
        cursor = conn.execute("SELECT COUNT(*) FROM historico_setor")
        total_antes = cursor.fetchone()[0]
        print(f"📊 Total antes: {total_antes} registros")
        
        registros_removidos = 0
        
        # 1. Números fictícios
        cursor = conn.execute("""
            DELETE FROM historico_setor 
            WHERE numero LIKE 'PROC%' 
            OR numero LIKE 'TEST%' 
            OR numero LIKE 'DEMO%'
            OR numero LIKE 'EXAMPLE%'
            OR numero LIKE 'SAMPLE%'
            OR numero LIKE 'SIM%'
            OR LOWER(numero) LIKE '%teste%'
            OR LOWER(numero) LIKE '%demo%'
            OR LOWER(numero) LIKE '%simulacao%'
            OR numero LIKE '%000%'
            OR numero LIKE '%123%'
            OR numero LIKE '%999%'
        """)
        removidos = cursor.rowcount
        registros_removidos += removidos
        if removidos > 0:
            print(f"   ❌ Removidos {removidos} registros com números fictícios")
        
        # 2. Analistas fictícios
        cursor = conn.execute("""
            DELETE FROM historico_setor 
            WHERE LOWER(TRIM(analista)) IN (
                'teste', 'test', 'demo', 'example', 'sample',
                'admin', 'administrador', 'user', 'usuario',
                'analista1', 'analista2', 'analista3', 'analista4', 'analista5',
                'fulano', 'sicrano', 'beltrano', 'joao', 'maria',
                'simulacao', 'sim', 'faker'
            )
            OR analista LIKE 'Analista %'
            OR analista LIKE 'User %'
            OR analista LIKE 'Test %'
        """)
        removidos = cursor.rowcount
        registros_removidos += removidos
        if removidos > 0:
            print(f"   ❌ Removidos {removidos} registros com analistas fictícios")
        
        # 3. Registros recentes suspeitos
        cursor = conn.execute("""
            DELETE FROM historico_setor 
            WHERE DATE(criado_em) >= DATE('now', '-7 days')
            AND (
                LENGTH(TRIM(numero)) < 4
                OR interessado IS NULL
                OR interessado = ''
                OR assunto IS NULL
                OR assunto = ''
            )
        """)
        removidos = cursor.rowcount
        registros_removidos += removidos
        if removidos > 0:
            print(f"   ❌ Removidos {removidos} registros suspeitos recentes")
            
        # 4. Dados incompletos
        cursor = conn.execute("""
            DELETE FROM historico_setor 
            WHERE (numero IS NULL OR TRIM(numero) = '')
            OR (analista IS NULL OR TRIM(analista) = '')
        """)
        removidos = cursor.rowcount
        registros_removidos += removidos
        if removidos > 0:
            print(f"   ❌ Removidos {removidos} registros incompletos")
        
        # 5. Duplicatas
        cursor = conn.execute("""
            DELETE FROM historico_setor 
            WHERE id NOT IN (
                SELECT MIN(id) 
                FROM historico_setor 
                GROUP BY LOWER(TRIM(analista)), TRIM(numero), data_distribuicao
            )
        """)
        removidos = cursor.rowcount
        registros_removidos += removidos
        if removidos > 0:
            print(f"   ❌ Removidos {removidos} duplicados")
        
        conn.commit()
        
        # Contar depois
        cursor = conn.execute("SELECT COUNT(*) FROM historico_setor")
        total_depois = cursor.fetchone()[0]
        
        print(f"📊 Total depois: {total_depois} registros")
        print(f"🗑️  Removidos: {registros_removidos} registros")
        
        # Backup se necessário
        if registros_removidos > 0:
            try:
                os.makedirs('backups', exist_ok=True)
                stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                
                csv_path = f'backups/dados_limpos_{stamp}.csv'
                cursor = conn.execute('''
                    SELECT ordem, analista, numero, data_distribuicao, data_conclusao, 
                           interessado, assunto, setor_origem, setor_destino 
                    FROM historico_setor ORDER BY data_distribuicao DESC
                ''')
                rows = cursor.fetchall()
                
                with open(csv_path, 'w', newline='', encoding='utf-8') as fh:
                    writer = csv.writer(fh)
                    writer.writerow(['ordem','analista','numero','data_distribuicao','data_conclusao',
                                   'interessado','assunto','setor_origem','setor_destino'])
                    writer.writerows(rows)
                
                print(f"💾 Backup salvo: {csv_path}")
                
            except Exception as e:
                print(f"⚠️  Erro no backup: {e}")
        
        return total_antes, total_depois, registros_removidos
        
    except Exception as e:
        conn.rollback()
        print(f"❌ Erro: {e}")
        return None, None, 0
    finally:
        conn.close()

if __name__ == '__main__':
    print("=" * 60)
    print("🧹 LIMPEZA DE DADOS DE SIMULAÇÃO - SISTEMA SAR")
    print("=" * 60)
    
    if not os.path.exists('sar.db'):
        print("❌ Arquivo sar.db não encontrado!")
        print("Execute este script na pasta do projeto SAR.")
        sys.exit(1)
    
    resposta = input("⚠️  Deseja realmente limpar dados de simulação? (s/N): ")
    if resposta.lower() not in ['s', 'sim', 'y', 'yes']:
        print("❌ Operação cancelada pelo usuário.")
        sys.exit(0)
    
    antes, depois, removidos = limpar_dados_simulacao()
    
    print("\n" + "=" * 60)
    print("✅ LIMPEZA CONCLUÍDA")
    print("=" * 60)
    print(f"📊 Registros antes: {antes}")
    print(f"📊 Registros depois: {depois}")
    print(f"🗑️  Registros removidos: {removidos}")
    print("\nSua base de dados está limpa! 🎉")