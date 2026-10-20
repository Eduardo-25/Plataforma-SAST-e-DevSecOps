"""Somente para análise estática. NÃO execute este arquivo."""
import sqlite3

conexao = sqlite3.connect(":memory:")
cursor = conexao.cursor()
nome = input("Nome: ")
consulta = "SELECT id FROM usuarios WHERE nome = '" + nome + "'"
cursor.execute(consulta)
