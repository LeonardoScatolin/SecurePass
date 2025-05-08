from flask import Flask, render_template, request, redirect, url_for, flash, session
from auth import (
    cadastrar_usuario,
    autenticar_usuario,
    gerar_token_recuperacao,
    redefinir_senha_com_token,
    buscar_usuario_por_username,
    validar_senha_forte
)
from database import iniciar_db
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE_NAME = "usuarios.db"

@app.before_request
def inicializar_banco():
    if not os.path.exists(DATABASE_NAME):
        iniciar_db()

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html', username=session.get('username'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['password']
        confirm_senha = request.form['confirm_password']

        if senha != confirm_senha:
            flash('As senhas não coincidem.', 'danger')
            return redirect(url_for('register'))

        sucesso, mensagem = cadastrar_usuario(username, senha)
        if sucesso:
            flash(mensagem, 'success')
            return redirect(url_for('login'))
        else:
            flash(mensagem, 'danger')
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        senha = request.form['password']
        sucesso, mensagem, user_id = autenticar_usuario(username, senha)
        if sucesso:
            session['user_id'] = user_id
            session['username'] = username
            flash(mensagem, 'success')
            return redirect(url_for('index'))
        else:
            flash(mensagem, 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

@app.route('/request-password-reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email'] # Simplificando para username
        user_id = buscar_usuario_por_username(username_or_email)
        if user_id:
            token = gerar_token_recuperacao(user_id)
            if token:
                # Em uma aplicação real, envie este token por e-mail.
                # Aqui, vamos exibi-lo ou passar para uma página de confirmação.
                flash(f'Token de recuperação gerado. Em um app real, isso seria enviado por email.', 'info')
                # Para fins de teste, podemos redirecionar para a página de reset com o token.
                # Não é seguro para produção, mas facilita o teste local.
                # flash(f'Use este token para redefinir: {token}', 'info')
                # return redirect(url_for('reset_password_with_token', token=token))
                # Idealmente, o usuário clicaria em um link no e-mail:
                reset_url = url_for('reset_password_with_token', token=token, _external=True)
                flash(f'Link para redefinição: {reset_url}', 'success')
                # Simulação: Apenas informamos que o token foi "enviado"
                return render_template('password_reset_requested.html', username=username_or_email, token_info=f"Token (para teste): {token} - Link: {reset_url}")

            else:
                flash('Não foi possível gerar o token de recuperação. Tente novamente.', 'danger')
        else:
            flash('Usuário não encontrado.', 'warning')
        return redirect(url_for('request_password_reset'))
    return render_template('request_password_reset.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_with_token(token):
    if request.method == 'POST':
        nova_senha = request.form['new_password']
        confirm_nova_senha = request.form['confirm_new_password']

        if nova_senha != confirm_nova_senha:
            flash('As novas senhas não coincidem.', 'danger')
            return redirect(url_for('reset_password_with_token', token=token))

        valida, msg_senha = validar_senha_forte(nova_senha)
        if not valida:
            flash(msg_senha, 'danger')
            return redirect(url_for('reset_password_with_token', token=token))

        sucesso, mensagem = redefinir_senha_com_token(token, nova_senha)
        if sucesso:
            flash(mensagem, 'success')
            return redirect(url_for('login'))
        else:
            flash(mensagem, 'danger')
            return redirect(url_for('reset_password_with_token', token=token))
            
    return render_template('reset_password.html', token=token)

if __name__ == '__main__':
    if not os.path.exists(DATABASE_NAME):
        print("Criando banco de dados inicial...")
        iniciar_db()
    app.run(debug=True)