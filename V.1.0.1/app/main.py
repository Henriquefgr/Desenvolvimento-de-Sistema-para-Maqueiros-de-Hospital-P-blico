import hashlib
import uuid
import datetime
import unittest

# Classes de Autenticação

class Usuario:
    """
    Representa um usuário com autenticação.
    """
    def __init__(self, username, password, role):
        self.username = username
        # A senha é armazenada como um hash para maior segurança
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.role = role  # Role pode ser "maqueiro" ou "admin"

    def verificar_senha(self, password):
        """
        Verifica se a senha fornecida corresponde ao hash armazenado.
        """
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash


class SistemaAutenticacao:
    """
    Gerencia a autenticação de usuários.
    """
    def __init__(self):
        self.usuarios = {}

    def adicionar_usuario(self, usuario):
        """
        Adiciona um usuário ao sistema de autenticação.
        """
        if usuario.username in self.usuarios:
            raise ValueError("Usuario já cadastrado.")
        self.usuarios[usuario.username] = usuario

    def autenticar(self, username, password):
        """
        Autentica um usuario com base no username e senha fornecidos.
        """
        usuario = self.usuarios.get(username)
        if usuario and usuario.verificar_senha(password):
            return usuario
        return None


# Classes de Entidade (Paciente, SolicitacaoTransporte, Maqueiro)

class Paciente:
    """
    Representa um paciente com informacoes sobre seu nome, localizacao e status.
    """
    def __init__(self, nome, localizacao):
        self.id_paciente = str(uuid.uuid4())
        self.nome = nome
        self.localizacao = localizacao
        self.status = "Aguardando transporte"


class SolicitacaoTransporte:
    """
    Representa uma solicitacao de transporte de um paciente.
    """
    def __init__(self, paciente, destino, prioridade):
        self.id_solicitacao = str(uuid.uuid4())
        self.paciente = paciente
        self.destino = destino
        self.prioridade = prioridade
        self.status = "Aguardando transporte"
        self.incidentes = []

    def atualizar_status(self, status):
        """
        Atualiza o status da solicitacao e do paciente associado.
        """
        self.status = status
        self.paciente.status = status

    def registrar_incidente(self, descricao, maqueiro_responsavel):
        """
        Registra um incidente associado a solicitacao.
        """
        data_hora = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        incidente = {
            "data_hora": data_hora,
            "descricao": descricao,
            "maqueiro_responsavel": maqueiro_responsavel.nome
        }
        self.incidentes.append(incidente)



class HistoricoSolicitacoes:
    """
    Classe que gerencia o historico de solicitacoes realizadas.
    """
    def __init__(self):
        self.registros = []

    def adicionar_registro(self, solicitacao):
        """Adiciona um registro de solicitacao no historico."""
        self.registros.append(solicitacao)

    def visualizar_historico(self):
        """Exibe os registros do historico, incluindo detalhes de incidentes."""
        print("\n--- Histórico de Solicitacoes ---")
        for solicitacao in self.registros:
            print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, "
                  f"Destino: {solicitacao.destino}, Status: {solicitacao.status}, "
                  f"Prioridade: {solicitacao.prioridade}")
            if solicitacao.incidentes:
                print("  -> Incidentes:")
                for incidente in solicitacao.incidentes:
                    print(f"     - {incidente['data_hora']}: {incidente['descricao']} (Maqueiro: {incidente['maqueiro_responsavel']})")

class IDNaoEncontradoError(Exception):
    """Exceção lançada quando um ID não é encontrado no sistema."""
    pass

class OperacaoInvalidaError(Exception):
    """Exceção lançada quando uma operação inválida é tentada."""
    pass


class Maqueiro:
    """
    Representa um maqueiro que gerencia solicitacoes de transporte.
    """
    def __init__(self, nome, historico):
        self.id_maqueiro = str(uuid.uuid4())
        self.nome = nome
        self.solicitacoes = []
        self.historico = historico

    def visualizar_solicitacoes(self):
        """Exibe as solicitacoes atribuidas ao maqueiro, ordenadas por prioridade."""
        print("\n--- Solicitacoes do Maqueiro ---")
        for solicitacao in sorted(self.solicitacoes, key=lambda x: x.prioridade):
            print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, "
                  f"Destino: {solicitacao.destino}, Status: {solicitacao.status}, "
                  f"Prioridade: {solicitacao.prioridade}")

    def aceitar_solicitacao(self, id_solicitacao):
        try:
            solicitacao = next(s for s in self.solicitacoes if s.id_solicitacao == id_solicitacao)
            solicitacao.atualizar_status("Em transporte")
            print(f"Solicitação {id_solicitacao} aceita por {self.nome}.")
            self.historico.adicionar_registro(solicitacao)
        except StopIteration:
            raise IDNaoEncontradoError(f"Solicitação com ID {id_solicitacao} não encontrada.")


    def recusar_solicitacao(self, id_solicitacao):
        try:
            solicitacao = next(s for s in self.solicitacoes if s.id_solicitacao == id_solicitacao)
            solicitacao.atualizar_status("Recusada")
            print(f"Solicitação {id_solicitacao} recusada por {self.nome}.")
            self.historico.adicionar_registro(solicitacao)
        except StopIteration:
            raise IDNaoEncontradoError(f"Solicitação com ID {id_solicitacao} não encontrada.")

    def concluir_transporte(self, id_solicitacao):
        try:
            solicitacao = next(s for s in self.solicitacoes if s.id_solicitacao == id_solicitacao)
            solicitacao.atualizar_status("Chegou ao destino")
            print(f"Solicitação {id_solicitacao} concluída por {self.nome}.")
            self.historico.adicionar_registro(solicitacao)
        except StopIteration:
            raise IDNaoEncontradoError(f"Solicitação com ID {id_solicitacao} não encontrada.")

    def relatar_incidente(self, id_solicitacao, descricao):
        try:
            solicitacao = next(s for s in self.solicitacoes if s.id_solicitacao == id_solicitacao)
            solicitacao.registrar_incidente(descricao, self)
            solicitacao.atualizar_status("Incidente relatado")
            print(f"Incidente relatado na solicitação {id_solicitacao}: {descricao}.")
            self.historico.adicionar_registro(solicitacao)
        except StopIteration:
            raise IDNaoEncontradoError(f"Solicitação com ID {id_solicitacao} não encontrada.")



# Sistema de Transporte de Pacientes

class SistemaTransporte:
    def __init__(self):
        self.maqueiros = []
        self.solicitacoes = []

    def adicionar_maqueiro(self, maqueiro):
        self.maqueiros.append(maqueiro)

    def criar_solicitacao(self, paciente, destino, prioridade):
        solicitacao = SolicitacaoTransporte(paciente, destino, prioridade)
        self.solicitacoes.append(solicitacao)
        self.solicitacoes.sort(key=lambda x: x.prioridade)  # Ordena globalmente por prioridade
        return solicitacao


# Funções de CLI

# Função para exibir o menu principal
def exibir_menu():
    print("\n--- Menu Principal ---")
    print("1. Autenticar-se")
    print("2. Listar Pacientes")
    print("3. Listar Todas as Solicitacoes")
    print("4. Sair")

# Função para listar todos os pacientes cadastrados
def listar_pacientes(sistema_transporte):
    print("\n--- Lista de Pacientes ---")
    for solicitacao in sistema_transporte.solicitacoes:
        paciente = solicitacao.paciente
        print(f"ID: {paciente.id_paciente}, Nome: {paciente.nome}, Localizacao: {paciente.localizacao}, Status: {paciente.status}")

# Função para listar todas as solicitações
def listar_solicitacoes(sistema_transporte):
    print("\n--- Lista de Solicitacoes ---")
    for solicitacao in sistema_transporte.solicitacoes:
        print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, Destino: {solicitacao.destino}, Prioridade: {solicitacao.prioridade}, Status: {solicitacao.status}")

# Função de menu para o maqueiro
def menu_maqueiro(maqueiro):
    print(f"\n--- Bem-vindo, {maqueiro.nome} ---")
    print("1. Visualizar Solicitacoes")
    print("2. Aceitar Solicitacao (Forneça o ID da solicitacao)")
    print("3. Recusar Solicitacao (Forneça o ID da solicitacao)")
    print("4. Atualizar Solicitacao (Forneça o ID e os dados a serem atualizados)")
    print("5. Concluir Transporte (Forneça o ID da solicitacao)")
    print("6. Visualizar Historico")
    print("7. Voltar ao Menu Principal")

# menu do maqueiro
def executar_menu_maqueiro(maqueiro):
    while True:
        menu_maqueiro(maqueiro)
        escolha_maqueiro = input("Escolha uma opção: ").strip()

        try:
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
                maqueiro.historico.visualizar_historico()
            elif escolha_maqueiro == '7':
                break
            else:
                raise OperacaoInvalidaError("Opção inválida. Escolha entre 1 e 7.")
        except (IDNaoEncontradoError, OperacaoInvalidaError) as e:
            print(f"Erro: {e}")
        except Exception as e:
            print(f"Ocorreu um erro inesperado: {e}")

def listar_pacientes(sistema_transporte):
    try:
        if not sistema_transporte.solicitacoes:
            print("\nNenhum paciente cadastrado no sistema.")
            return
        print("\n--- Lista de Pacientes ---")
        for solicitacao in sistema_transporte.solicitacoes:
            paciente = solicitacao.paciente
            print(f"ID: {paciente.id_paciente}, Nome: {paciente.nome}, Localização: {paciente.localizacao}, Status: {paciente.status}")
    except Exception as e:
        print(f"Erro ao listar pacientes: {e}")


def listar_solicitacoes(sistema_transporte):
    try:
        if not sistema_transporte.solicitacoes:
            print("\nNenhuma solicitação cadastrada no sistema.")
            return
        print("\n--- Lista de Solicitações ---")
        for solicitacao in sistema_transporte.solicitacoes:
            print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, "
                  f"Destino: {solicitacao.destino}, Prioridade: {solicitacao.prioridade}, Status: {solicitacao.status}")
    except Exception as e:
        print(f"Erro ao listar solicitações: {e}")           

# Função para exibir o menu de administrador
def menu_admin():
    print("\n--- Bem-vindo, Administrador ---")
    print("1. Visualizar Todos os Maqueiros")
    print("2. Voltar ao Menu Principal")

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
                            print("Opção inválida. Escolha entre 1 e 7.")
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
                            print("Opção inválida. Escolha entre 1 e 2.")
            else:
                print("Falha na autenticação. Verifique o nome de usuário e a senha.")
        elif escolha == '2':
            listar_pacientes(sistema_transporte)
        elif escolha == '3':
            listar_solicitacoes(sistema_transporte)
        elif escolha == '4':
            print("Saindo do sistema.")
            break
        else:
            print("Opção inválida. Escolha entre 1 e 4.")

# Iniciar o sistema CLI
if __name__ == "__main__":
    executar_cli()

# Implementação de testes automatizados

class TestSistemaTransporte(unittest.TestCase):

    def setUp(self):
        # Inicializando o sistema para testes
        self.auth_system = SistemaAutenticacao()
        self.auth_system.adicionar_usuario(Usuario("maqueiro1", "senha123", "maqueiro"))
        self.auth_system.adicionar_usuario(Usuario("admin", "adminpass", "admin"))

        self.sistema = SistemaTransporte()
        self.historico = HistoricoSolicitacoes()

        self.paciente1 = Paciente(1, "Paciente 1", "Sala 101")
        self.paciente2 = Paciente(2, "Paciente 2", "Sala 102")
        
        self.maqueiro = Maqueiro(1, "João", self.historico)
        self.sistema.adicionar_maqueiro(self.maqueiro)

    def test_criar_solicitacao(self):
        solicitacao = self.sistema.criar_solicitacao(self.paciente1, "Raio-X", "Alta")
        self.assertEqual(solicitacao.paciente, self.paciente1)
        self.assertEqual(solicitacao.destino, "Raio-X")
        self.assertEqual(solicitacao.prioridade, "Alta")
        self.assertEqual(solicitacao.status, "Aguardando transporte")

    def test_aceitar_solicitacao(self):
        solicitacao = self.sistema.criar_solicitacao(self.paciente1, "Raio-X", "Alta")
        self.maqueiro.aceitar_solicitacao(solicitacao.id_solicitacao)
        self.assertEqual(solicitacao.status, "Em transporte")
        self.assertEqual(self.paciente1.status, "Em transporte")

    def test_recusar_solicitacao(self):
        solicitacao = self.sistema.criar_solicitacao(self.paciente2, "Tomografia", "Média")
        self.maqueiro.recusar_solicitacao(solicitacao.id_solicitacao)
        self.assertEqual(solicitacao.status, "Recusada")
        self.assertEqual(self.paciente2.status, "Aguardando transporte")

    def test_concluir_transporte(self):
        solicitacao = self.sistema.criar_solicitacao(self.paciente1, "Raio-X", "Alta")
        self.maqueiro.aceitar_solicitacao(solicitacao.id_solicitacao)
        self.maqueiro.concluir_transporte(solicitacao.id_solicitacao)
        self.assertEqual(solicitacao.status, "Chegou ao destino")
        self.assertEqual(self.paciente1.status, "Chegou ao destino")

    def test_relatar_incidente(self):
        solicitacao = self.sistema.criar_solicitacao(self.paciente1, "Raio-X", "Alta")
        self.maqueiro.aceitar_solicitacao(solicitacao.id_solicitacao)

    def setUp(self):
        self.historico = HistoricoSolicitacoes()
        self.maqueiro = Maqueiro("João", self.historico)
        self.sistema = SistemaTransporte()
        self.sistema.adicionar_maqueiro(self.maqueiro)

    def test_criar_solicitacao(self):
        paciente = Paciente("Paciente 1", "Sala 101")
        solicitacao = self.sistema.criar_solicitacao(paciente, "Raio-X", "Alta")
        self.assertEqual(solicitacao.paciente.nome, "Paciente 1")
        self.assertEqual(solicitacao.destino, "Raio-X")

if __name__ == "__main__":
    unittest.main()
