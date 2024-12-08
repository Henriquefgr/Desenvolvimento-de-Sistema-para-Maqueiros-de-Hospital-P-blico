import hashlib
import uuid
import datetime
import unittest
from tkinter import messagebox, simpledialog

# Classes de Autenticação

class Usuario:
    """
    Representa um usuário com autenticação.
    """
    def __init__(self, username, password, role):
        self.username = username
        # A senha é armazenada como um hash para maior segurança
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.role = role  

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

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, simpledialog


class SistemaGUI:
    def __init__(self, root, sistema_transporte, auth_system):
        self.root = root
        self.sistema_transporte = sistema_transporte
        self.auth_system = auth_system
        self.usuario_autenticado = None

        # Configuração inicial
        self.root.title("Sistema de Transporte de Pacientes")
        self.root.geometry("800x600")

        # Tela inicial
        self.tela_login()

    def tela_login(self):
        # Limpar tela
        self.limpar_tela()

        # Criar widgets
        ttk.Label(self.root, text="Login", font=("Arial", 16), bootstyle="primary").pack(pady=20)

        ttk.Label(self.root, text="Usuário:").pack(pady=5)
        self.entry_username = ttk.Entry(self.root, bootstyle="info")
        self.entry_username.pack(pady=5)

        ttk.Label(self.root, text="Senha:").pack(pady=5)
        self.entry_password = ttk.Entry(self.root, show="*", bootstyle="info")
        self.entry_password.pack(pady=5)

        ttk.Button(self.root, text="Entrar", command=self.autenticar_usuario, bootstyle="success").pack(pady=10)

    def autenticar_usuario(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()
        self.usuario_autenticado = self.auth_system.autenticar(username, password)

        if self.usuario_autenticado:
            if self.usuario_autenticado.role == "maqueiro":
                self.tela_maqueiro()
            elif self.usuario_autenticado.role == "admin":
                self.tela_admin()
        else:
            messagebox.showerror("Erro de Login", "Usuário ou senha inválidos!")

    def tela_maqueiro(self):
        # Limpar tela
        self.limpar_tela()

        ttk.Label(self.root, text=f"Bem-vindo, {self.usuario_autenticado.username}", font=("Arial", 16),
                  bootstyle="primary").pack(pady=20)
        ttk.Button(self.root, text="Visualizar Solicitações", command=self.visualizar_solicitacoes,
                   bootstyle="info").pack(pady=5)
        ttk.Button(self.root, text="Registrar Incidente", command=self.registrar_incidente,
                   bootstyle="warning").pack(pady=5)
        ttk.Button(self.root, text="Concluir Transporte", command=self.concluir_transporte,
                   bootstyle="success").pack(pady=5)
        ttk.Button(self.root, text="Sair", command=self.tela_login, bootstyle="danger").pack(pady=20)

    def visualizar_solicitacoes(self):
        # Limpar tela
        self.limpar_tela()

        ttk.Label(self.root, text="Solicitações de Transporte", font=("Arial", 16), bootstyle="primary").pack(pady=20)

        frame = ttk.Treeview(self.root, columns=("ID", "Paciente", "Destino", "Prioridade", "Status"), show="headings",
                             bootstyle="info")
        frame.heading("ID", text="ID")
        frame.heading("Paciente", text="Paciente")
        frame.heading("Destino", text="Destino")
        frame.heading("Prioridade", text="Prioridade")
        frame.heading("Status", text="Status")
        frame.pack(fill="both", expand=True)

        for solicitacao in self.sistema_transporte.solicitacoes:
            frame.insert("", "end", values=(
                solicitacao.id_solicitacao,
                solicitacao.paciente.nome,
                solicitacao.destino,
                solicitacao.prioridade,
                solicitacao.status,
            ))

        ttk.Button(self.root, text="Voltar", command=self.tela_maqueiro, bootstyle="secondary").pack(pady=10)

    def registrar_incidente(self):
        self.exibir_prompt("Digite o ID da solicitação para registrar um incidente:", self.realizar_registro_incidente)

    def realizar_registro_incidente(self, id_solicitacao):
        solicitacao = self.buscar_solicitacao(id_solicitacao)
        if solicitacao:
            incidente = self.exibir_prompt_texto("Descreva o incidente:")
            if incidente:
                self.usuario_autenticado.relatar_incidente(solicitacao.id_solicitacao, incidente)
                messagebox.showinfo("Sucesso", f"Incidente registrado para {solicitacao.paciente.nome}")
            else:
                messagebox.showerror("Erro", "Descrição do incidente não pode ser vazia.")
        else:
            messagebox.showerror("Erro", "Solicitação não encontrada.")

    def concluir_transporte(self):
        self.exibir_prompt("Digite o ID da solicitação para concluir:", self.realizar_conclusao_transporte)

    def realizar_conclusao_transporte(self, id_solicitacao):
        solicitacao = self.buscar_solicitacao(id_solicitacao)
        if solicitacao:
            self.usuario_autenticado.concluir_transporte(solicitacao.id_solicitacao)
            messagebox.showinfo("Sucesso", f"Transporte concluído para {solicitacao.paciente.nome}")
        else:
            messagebox.showerror("Erro", "Solicitação não encontrada.")

    def exibir_prompt(self, mensagem, callback):
        # Janela de entrada para obter o ID de uma solicitação
        janela_prompt = ttk.Toplevel(self.root)
        janela_prompt.title("Entrada")
        janela_prompt.geometry("300x200")

        ttk.Label(janela_prompt, text=mensagem, bootstyle="info").pack(pady=10)
        entry = ttk.Entry(janela_prompt, bootstyle="primary")
        entry.pack(pady=5)

        def confirmar():
            callback(entry.get())
            janela_prompt.destroy()

        ttk.Button(janela_prompt, text="Confirmar", command=confirmar, bootstyle="success").pack(pady=10)

    def exibir_prompt_texto(self, mensagem):
        # Retorna o texto digitado pelo usuário
        return simpledialog.askstring("Entrada", mensagem)

    def buscar_solicitacao(self, id_solicitacao):
        # Encontra a solicitação pelo ID
        for solicitacao in self.sistema_transporte.solicitacoes:
            if solicitacao.id_solicitacao == id_solicitacao:
                return solicitacao
        return None

    def limpar_tela(self):
        for widget in self.root.winfo_children():
            widget.destroy()


# Configuração inicial
if __name__ == "__main__":
    auth_system = SistemaAutenticacao()
    auth_system.adicionar_usuario(Usuario("maqueiro1", "senha123", "maqueiro"))
    auth_system.adicionar_usuario(Usuario("admin", "adminpass", "admin"))

    sistema_transporte = SistemaTransporte()
    historico = HistoricoSolicitacoes()

    maqueiro = Maqueiro("João", historico)
    sistema_transporte.adicionar_maqueiro(maqueiro)

    paciente1 = Paciente("Paciente 1", "Sala 101")
    paciente2 = Paciente("Paciente 2", "Sala 102")
    sistema_transporte.criar_solicitacao(paciente1, "Raio-X", "Alta")
    sistema_transporte.criar_solicitacao(paciente2, "Tomografia", "Média")

    root = ttk.Window(themename="darkly")  # Modernização com tema da biblioteca ttkbootstrap
    app = SistemaGUI(root, sistema_transporte, auth_system)
    root.mainloop()



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
