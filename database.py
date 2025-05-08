import sqlite3

def iniciar_db():
    conexao = sqlite3.connect("usuarios.db")
    cursor = conexao.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            senha_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tokens_recuperacao (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            data_expiracao DATETIME NOT NULL,
            utilizado BOOLEAN DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES usuarios (id)
        )
    """)
    conexao.commit()
    conexao.close()

if __name__ == "__main__":
    iniciar_db()