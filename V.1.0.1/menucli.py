import hashlib
import uuid

# -------------------------------------------
# Classes de Entidade (Paciente, SolicitacaoTransporte, Maqueiro)
# -------------------------------------------

class Paciente:
    def __init__(self, nome, localizacao):
        self.id_paciente = str(uuid.uuid4())  # Gerando um ID único para o paciente
        self.nome = nome
        self.localizacao = localizacao
        self.status = "Aguardando transporte"

class SolicitacaoTransporte:
    def __init__(self, paciente, destino, prioridade):
        self.id_solicitacao = str(uuid.uuid4())  # Gerando um ID único para a solicitação
        self.paciente = paciente
        self.destino = destino
        self.prioridade = prioridade
        self.status = "Aguardando transporte"

    def atualizar_status(self, status):
        self.status = status
        self.paciente.status = status

class HistoricoSolicitacoes:
    def __init__(self):
        self.registros = []

    def adicionar_registro(self, solicitacao):
        self.registros.append({
            "id_solicitacao": solicitacao.id_solicitacao,
            "paciente": solicitacao.paciente.nome,
            "destino": solicitacao.destino,
            "prioridade": solicitacao.prioridade,
            "status": solicitacao.status
        })

    def visualizar_historico(self):
        for registro in self.registros:
            print(f"ID: {registro['id_solicitacao']}, Paciente: {registro['paciente']}, Destino: {registro['destino']}, Status: {registro['status']}, Prioridade: {registro['prioridade']}")

class Maqueiro:
    def __init__(self, nome, historico):
        self.id_maqueiro = str(uuid.uuid4())  # ID único para cada maqueiro
        self.nome = nome
        self.solicitacoes = []
        self.historico = historico

    def visualizar_solicitacoes(self):
        for solicitacao in sorted(self.solicitacoes, key=lambda x: x.prioridade):
            print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, Destino: {solicitacao.destino}, Status: {solicitacao.status}, Prioridade: {solicitacao.prioridade}")

    def aceitar_solicitacao(self, id_solicitacao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.atualizar_status("Em transporte")
                print(f"Solicitação {id_solicitacao} aceita por {self.nome}.")
                self.historico.adicionar_registro(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

    def recusar_solicitacao(self, id_solicitacao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.atualizar_status("Recusada")
                print(f"Solicitação {id_solicitacao} recusada por {self.nome}.")
                self.historico.adicionar_registro(solicitacao)
                self.solicitacoes.remove(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

    def relatar_incidente(self, id_solicitacao, descricao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.atualizar_status("Incidente relatado")
                print(f"Incidente relatado na solicitação {id_solicitacao}: {descricao}.")
                self.historico.adicionar_registro(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

    def concluir_transporte(self, id_solicitacao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.atualizar_status("Chegou ao destino")
                print(f"Solicitação {id_solicitacao} concluída por {self.nome}.")
                self.historico.adicionar_registro(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

# -------------------------------------------
# Sistema de Autenticação
# -------------------------------------------

class Usuario:
    def __init__(self, username, password, role):
        self.username = username
        self.password = self.hash_password(password)  # Armazenando senha de forma segura
        self.role = role

    def hash_password(self, password):
        """Gera o hash da senha usando SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Verifica se a senha fornecida corresponde ao hash armazenado"""
        return self.password == self.hash_password(password)

class SistemaAutenticacao:
    def __init__(self):
        self.usuarios = []

    def adicionar_usuario(self, usuario):
        self.usuarios.append(usuario)

    def autenticar(self, username, password):
        """Autentica o usuário com base no nome de usuário e senha"""
        for usuario in self.usuarios:
            if usuario.username == username and usuario.check_password(password):
                return usuario
        return None

# -------------------------------------------
# Sistema de Transporte de Pacientes
# -------------------------------------------

class SistemaTransporte:
    def __init__(self):
        self.maqueiros = []
        self.solicitacoes = []

    def adicionar_maqueiro(self, maqueiro):
        self.maqueiros.append(maqueiro)

    def criar_solicitacao(self, paciente, destino, prioridade):
        solicitacao = SolicitacaoTransporte(paciente, destino, prioridade)
        self.solicitacoes.append(solicitacao)
        return solicitacao

# -------------------------------------------
# Funções de CLI
# -------------------------------------------

# Função para exibir o menu principal
def exibir_menu():
    print("\n--- Menu Principal ---")
    print("1. Autenticar-se")
    print("2. Sair")

# Função para exibir o menu de maqueiro
def menu_maqueiro(maqueiro):
    print(f"\n--- Bem-vindo, {maqueiro.nome} ---")
    print("1. Visualizar Solicitações")
    print("2. Aceitar Solicitação")
    print("3. Recusar Solicitação")
    print("4. Relatar Incidente")
    print("5. Concluir Transporte")
    print("6. Visualizar Histórico")
    print("7. Sair")

# Função para exibir o menu de administrador
def menu_admin():
    print("\n--- Bem-vindo, Administrador ---")
    print("1. Visualizar Todos os Maqueiros")
    print("2. Sair")

# Função principal que executa o CLI
def executar_cli():
    # Sistema de autenticação
    auth_system = SistemaAutenticacao()
    auth_system.adicionar_usuario(Usuario("maqueiro1", "senha123", "maqueiro"))
    auth_system.adicionar_usuario(Usuario("admin", "adminpass", "admin"))
    
    # Sistema de transporte
    historico = HistoricoSolicitacoes()
    maqueiro = Maqueiro("João", historico)
    sistema_transporte = SistemaTransporte()
    sistema_transporte.adicionar_maqueiro(maqueiro)
    
    # Criando pacientes e solicitações
    paciente1 = Paciente("Paciente 1", "Sala 101")
    paciente2 = Paciente("Paciente 2", "Sala 102")
    solicitacao1 = sistema_transporte.criar_solicitacao(paciente1, "Raio-X", "Alta")
    solicitacao2 = sistema_transporte.criar_solicitacao(paciente2, "Tomografia", "Média")
    
    maqueiro.solicitacoes.append(solicitacao1)
    maqueiro.solicitacoes.append(solicitacao2)
    
    # Loop principal da CLI
    while True:
        exibir_menu()
        escolha = input("Escolha uma opção: ").strip()
        
        if escolha == '1':
            # Autenticação
            username = input("Digite o nome de usuário: ").strip()
            password = input("Digite a senha: ").strip()
            
            usuario_autenticado = auth_system.autenticar(username, password)
            if usuario_autenticado:
                if usuario_autenticado.role == "maqueiro":
                    while True:
                        menu_maqueiro(maqueiro)
                        escolha_maqueiro = input("Escolha uma opção: ").strip()
                        
                        if escolha_maqueiro == '1':
                            maqueiro.visualizar_solicitacoes()
                        elif escolha_maqueiro == '2':
                            id_solicitacao = input("Digite o ID da solicitação para aceitar: ").strip()
                            maqueiro.aceitar_solicitacao(id_solicitacao)
                        elif escolha_maqueiro == '3':
                            id_solicitacao = input("Digite o ID da solicitação para recusar: ").strip()
                            maqueiro.recusar_solicitacao(id_solicitacao)
                        elif escolha_maqueiro == '4':
                            id_solicitacao = input("Digite o ID da solicitação para relatar incidente: ").strip()
                            descricao = input("Digite a descrição do incidente: ").strip()
                            maqueiro.relatar_incidente(id_solicitacao, descricao)
                        elif escolha_maqueiro == '5':
                            id_solicitacao = input("Digite o ID da solicitação para concluir: ").strip()
                            maqueiro.concluir_transporte(id_solicitacao)
                        elif escolha_maqueiro == '6':
                            historico.visualizar_historico()
                        elif escolha_maqueiro == '7':
                            break
                        else:
                            print("Opção inválida.")
                elif usuario_autenticado.role == "admin":
                    while True:
                        menu_admin()
                        escolha_admin = input("Escolha uma opção: ").strip()
                        
                        if escolha_admin == '1':
                            print("\nLista de Maqueiros:")
                            for maqueiro in sistema_transporte.maqueiros:
                                print(f"ID: {maqueiro.id_maqueiro}, Nome: {maqueiro.nome}")
                        elif escolha_admin == '2':
                            break
                        else:
                            print("Opção inválida.")
            else:
                print("Falha na autenticação.")
        elif escolha == '2':
            print("Saindo do sistema.")
            break
        else:
            print("Opção inválida.")

# Iniciar o sistema CLI
if __name__ == "__main__":
    executar_cli()

