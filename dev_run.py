# ARQUIVO DE DESENVOLVIMENTO
# Use este arquivo apenas para testes durante o desenvolvimento
# Para produção, use app.py como ponto de entrada

import sys
print("Antes de importar create_app")
from app.__init__ import create_app
print("Após importar create_app")
from flask import render_template

print("Antes de criar app")
app = create_app()
print("Após criar app")

@app.route('/dev-test')
def hello():
    return "Olá! A IA de Relacionamento está funcionando! (Ambiente de Desenvolvimento)"

if __name__ == '__main__':
    print("Antes de iniciar o servidor")
    app.run(debug=True, use_reloader=False, port=8080)
    print("Servidor iniciado") 