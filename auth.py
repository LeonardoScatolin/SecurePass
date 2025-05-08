import hashlib
import os
import sqlite3
import re
import secrets
from datetime import datetime, timedelta

DATABASE_NAME = "usuarios.db"

def validar_senha_forte(senha):
    if len(senha) < 8:
        return False, "A senha deve ter no mínimo 8 caracteres."
    if not re.search(r"[a-z]", senha):
        return False, "A senha deve conter pelo menos uma letra minúscula."
    if not re.search(r"[A-Z]", senha):
        return False, "A senha deve conter pelo menos uma letra maiúscula."
    if not re.search(r"[0-9]", senha):
        return False, "A senha deve conter pelo menos um número."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", senha):
        return False, "A senha deve conter pelo menos um símbolo."
    return True, ""

def gerar_hash_senha(senha):
    salt = os.urandom(16).hex()
    senha_com_salt = senha + salt
    senha_hash = hashlib.sha256(senha_com_salt.encode()).hexdigest()
    return senha_hash, salt

def cadastrar_usuario(username, senha):
    valida, mensagem = validar_senha_forte(senha)
    if not valida:
        return False, mensagem

    conexao = sqlite3.connect(DATABASE_NAME)
    cursor = conexao.cursor()
    try:
        senha_hash, salt = gerar_hash_senha(senha)
        cursor.execute("INSERT INTO usuarios (username, senha_hash, salt) VALUES (?, ?, ?)", (username, senha_hash, salt))
        conexao.commit()
        return True, f"Usuário {username} cadastrado com sucesso!"
    except sqlite3.IntegrityError:
        return False, "Nome de usuário já existe."
    finally:
        cursor.close()
        conexao.close()

def autenticar_usuario(username, senha):
    conexao = sqlite3.connect(DATABASE_NAME)
    cursor = conexao.cursor()
    cursor.execute("SELECT id, senha_hash, salt FROM usuarios WHERE username = ?", (username,))
    resultado = cursor.fetchone()
    cursor.close()
    conexao.close()

    if resultado:
        user_id, senha_hash_armazenado, salt_armazenado = resultado
        senha_teste = hashlib.sha256((senha + salt_armazenado).encode()).hexdigest()
        if senha_teste == senha_hash_armazenado:
            return True, "Acesso permitido!", user_id
        else:
            return False, "Senha incorreta!", None
    else:
        return False, "Usuário não encontrado.", None

def gerar_token_recuperacao(user_id):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    data_expiracao = datetime.now() + timedelta(hours=1)

    conexao = sqlite3.connect(DATABASE_NAME)
    cursor = conexao.cursor()
    try:
        cursor.execute("INSERT INTO tokens_recuperacao (user_id, token_hash, data_expiracao) VALUES (?, ?, ?)",
                       (user_id, token_hash, data_expiracao))
        conexao.commit()
        return token
    except sqlite3.Error as e:
        print(f"Erro ao gerar token: {e}")
        return None
    finally:
        cursor.close()
        conexao.close()

def verificar_token_e_obter_user_id(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conexao = sqlite3.connect(DATABASE_NAME)
    cursor = conexao.cursor()
    cursor.execute("""
        SELECT user_id, data_expiracao, utilizado 
        FROM tokens_recuperacao 
        WHERE token_hash = ?
    """, (token_hash,))
    resultado = cursor.fetchone()

    if not resultado:
        cursor.close()
        conexao.close()
        return None, "Token inválido."

    user_id, data_expiracao_str, utilizado = resultado
    data_expiracao = datetime.strptime(data_expiracao_str, '%Y-%m-%d %H:%M:%S.%f') # Ajustar formato se necessário

    if utilizado:
        cursor.close()
        conexao.close()
        return None, "Token já utilizado."
    
    if datetime.now() > data_expiracao:
        cursor.close()
        conexao.close()
        return None, "Token expirado."
    
    cursor.close()
    conexao.close()
    return user_id, "Token válido."


def redefinir_senha_com_token(token, nova_senha):
    user_id, msg = verificar_token_e_obter_user_id(token)
    if not user_id:
        return False, msg

    valida, mensagem_senha = validar_senha_forte(nova_senha)
    if not valida:
        return False, mensagem_senha

    nova_senha_hash, novo_salt = gerar_hash_senha(nova_senha)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conexao = sqlite3.connect(DATABASE_NAME)
    cursor = conexao.cursor()
    try:
        cursor.execute("UPDATE usuarios SET senha_hash = ?, salt = ? WHERE id = ?", 
                       (nova_senha_hash, novo_salt, user_id))
        cursor.execute("UPDATE tokens_recuperacao SET utilizado = 1 WHERE token_hash = ?", (token_hash,))
        conexao.commit()
        return True, "Senha redefinida com sucesso."
    except sqlite3.Error as e:
        return False, f"Erro ao redefinir senha: {e}"
    finally:
        cursor.close()
        conexao.close()

def buscar_usuario_por_username(username):
    conexao = sqlite3.connect(DATABASE_NAME)
    cursor = conexao.cursor()
    cursor.execute("SELECT id FROM usuarios WHERE username = ?", (username,))
    resultado = cursor.fetchone()
    cursor.close()
    conexao.close()
    return resultado[0] if resultado else None