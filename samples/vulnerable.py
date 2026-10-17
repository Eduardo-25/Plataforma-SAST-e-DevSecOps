"""Código propositalmente inseguro para demonstrar o scanner do CP1.
Não use este exemplo como código de produção.
"""

import subprocess

password = "admin123"  # SAST001: segredo hardcoded
entrada = input("Digite uma expressão: ")
resultado = eval(entrada)  # SAST002: execução dinâmica de código
subprocess.run("echo " + entrada, shell=True)  # SAST003: shell=True
