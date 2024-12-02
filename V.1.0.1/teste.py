import hashlib
import unittest

class Paciente:
    def __init__(self, id_paciente, nome, localizacao):
        self.id_paciente = id_paciente
        self.nome = nome
        self.localizacao = localizacao
        self.status = "Aguardando transporte"

class SolicitacaoTransporte:
    def __init__(self, id_solicitacao, paciente, destino, prioridade):
        self.id_solicitacao = id_solicitacao
        self.paciente = paciente
        self.destino = destino
        self.prioridade = prioridade
        self.status = "Aguardando transporte"

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
            print(registro)

class Maqueiro:
    def __init__(self, id_maqueiro, nome, historico):
        self.id_maqueiro = id_maqueiro
        self.nome = nome
        self.solicitacoes = []
        self.historico = historico

    def visualizar_solicitacoes(self):
        for solicitacao in sorted(self.solicitacoes, key=lambda x: x.prioridade):
            print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, Destino: {solicitacao.destino}, Status: {solicitacao.status}, Prioridade: {solicitacao.prioridade}")

    def aceitar_solicitacao(self, id_solicitacao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.status = "Em transporte"
                solicitacao.paciente.status = "Em transporte"
                print(f"Solicitação {id_solicitacao} aceita por {self.nome}.")
                self.historico.adicionar_registro(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

    def recusar_solicitacao(self, id_solicitacao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.status = "Recusada"
                solicitacao.paciente.status = "Aguardando transporte"
                print(f"Solicitação {id_solicitacao} recusada por {self.nome}.")
                self.historico.adicionar_registro(solicitacao)
                self.solicitacoes.remove(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

    def concluir_transporte(self, id_solicitacao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.status = "Chegou ao destino"
                solicitacao.paciente.status = "Chegou ao destino"
                print(f"Solicitação {id_solicitacao} concluída por {self.nome}.")
                self.historico.adicionar_registro(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

    def relatar_incidente(self, id_solicitacao, descricao):
        for solicitacao in self.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                solicitacao.status = "Incidente relatado"
                print(f"Incidente relatado na solicitação {id_solicitacao}: {descricao}.")
                self.historico.adicionar_registro(solicitacao)
                return
        print(f"Solicitação {id_solicitacao} não encontrada.")

class SistemaTransporte:
    def __init__(self):
        self.maqueiros = []
        self.solicitacoes = []
        self.proximos_id_solicitacao = 1

    def adicionar_maqueiro(self, maqueiro):
        self.maqueiros.append(maqueiro)

    def criar_solicitacao(self, paciente, destino, prioridade):
        solicitacao = SolicitacaoTransporte(self.proximos_id_solicitacao, paciente, destino, prioridade)
        self.solicitacoes.append(solicitacao)
        self.proximos_id_solicitacao += 1
        return solicitacao

    def visualizar_todas_solicitacoes(self):
        for solicitacao in sorted(self.solicitacoes, key=lambda x: x.prioridade):
            print(f"ID: {solicitacao.id_solicitacao}, Paciente: {solicitacao.paciente.nome}, Destino: {solicitacao.destino}, Status: {solicitacao.status}, Prioridade: {solicitacao.prioridade}")

class Usuario:
    def __init__(self, username, password, role):
        self.username = username
        self.password = self.hash_password(password)  # Armazenando senha em hash
        self.role = role

    def hash_password(self, password):
        """Criptografa a senha utilizando SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        """Verifica se a senha fornecida corresponde ao hash armazenado."""
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

# Exemplo de criação de usuários
auth_system = SistemaAutenticacao()
auth_system.adicionar_usuario(Usuario("maqueiro1", "senha123", "maqueiro"))
auth_system.adicionar_usuario(Usuario("admin", "adminpass", "admin"))

# Testando a autenticação
usuario_autenticado = auth_system.autenticar("maqueiro1", "senha123")
if usuario_autenticado:
    print(f"Usuário {usuario_autenticado.username} autenticado com sucesso!")
else:
    print("Falha na autenticação!")

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


