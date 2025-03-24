from app import create_app

# Criação da aplicação principal
app = create_app()

if __name__ == '__main__':
    # Ponto de entrada principal da aplicação
    print("Iniciando servidor na porta 5000...")
    app.run(debug=False, port=5000) 