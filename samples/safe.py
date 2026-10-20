"""Exemplo simples sem os três padrões detectados pelas regras iniciais."""

import os
import subprocess

password = os.getenv("APP_PASSWORD")
mensagem = input("Digite uma mensagem: ")
subprocess.run(["echo", mensagem], check=False)
