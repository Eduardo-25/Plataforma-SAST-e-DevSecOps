"""Consulta parametrizada: a entrada é enviada separadamente do texto SQL."""
import sqlite3

conexao = sqlite3.connect(":memory:")
cursor = conexao.cursor()
nome = input("Nome: ")
cursor.execute("SELECT id FROM usuarios WHERE nome = ?", (nome,))
