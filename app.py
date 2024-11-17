from flask import Flask, render_template, request, redirect, url_for, session, make_response, flash
from flask_socketio import SocketIO, send
import os
import sqlite3
import uuid
import datetime
from html import escape
from collections import defaultdict
from gevent import monkey

monkey.patch_all()

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'
ACCESS_CODE = "1234"

#socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins='*', transports=['websocket', 'polling'])

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Erreur rencontrée : {e}")
    return "Une erreur s'est produite.", 500

# Séquences d'échappement ANSI pour les couleurs
class Colors:
    RESET = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    YELLOW = "\033[93m"

# Dictionnaire pour stocker les timestamps des messages envoyés par utilisateur
user_messages = defaultdict(list)
MESSAGE_LIMIT = 2  # Limite de messages par seconde
TIME_FRAME = 1  # Temps en secondes pour la limitation

# Créer le fichier banned_user.txt s'il n'existe pas
if not os.path.exists('banned_user.txt'):
    with open('banned_user.txt', 'w') as f:
        f.write('')

# Créer le fichier de log s'il n'existe pas
if not os.path.exists('message_log.txt'):
    with open('message_log.txt', 'w') as f:
        f.write('')

# Initialisation de la base de données
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)''')  # Ajout de la table users
    conn.commit()
    conn.close()


def get_messages():
    try:
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute('SELECT id, username, message, created_at FROM messages')
        messages = c.fetchall()
        return messages  # Assurez-vous que cela renvoie tous les messages avec 4 colonnes
    except sqlite3.Error as e:
        print(f"Erreur SQLite: {e}")
        return []
    finally:
        conn.close()

def add_message(username, message):
    try:
        # Échapper le message pour éviter les failles XSS
        cleaned_message = escape(message)

        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        # Ajouter le message
        c.execute('INSERT INTO messages (username, message) VALUES (?, ?)', (username, cleaned_message))
        
        # Supprimer les messages les plus anciens si plus de 100
        c.execute('DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY created_at DESC LIMIT 100)')
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Erreur SQLite: {e}")
    finally:
        conn.close()


def log_message(username, user_id, message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('message_log.txt', 'a') as f:
        f.write(f"{timestamp} - Pseudo: {username}, ID: {user_id}, Message: {message}\n")

def add_ban_user(username):
    with open('banned_user.txt', 'a') as f:
        f.write(username + '\n')  # On stocke le nom d'utilisateur

def is_banned(username):
    with open('banned_user.txt', 'r') as f:
        banned_users = f.read().splitlines()
        return username in banned_users


def get_user_id_by_username(username):
    try:
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user:
            return str(user[0])
        return None
    except sqlite3.Error as e:
        print(f"Erreur SQLite lors de la recherche de l'utilisateur : {e}")
        return None
    finally:
        conn.close()

@app.route('/ban_user', methods=['POST'])
def ban_user():
    username = request.form.get('user_id')
    ban_code = request.form.get('ban_code')

    if ban_code == ACCESS_CODE:
        if username:
            add_ban_user(username)
            flash(f"Utilisateur {username} banni avec succès.", "admin-success")  # Catégorie 'admin-success'
        else:
            flash(f"Nom d'utilisateur {username} non trouvé.", "admin-error")  # Catégorie 'admin-error'
    else:
        flash("Code d'accès incorrect.", "admin-error")

    return redirect(url_for('admin'))

@app.route('/unban_user', methods=['POST'])
def unban_user():
    username = request.form.get('user_id')
    unban_code = request.form.get('unban_code')

    if unban_code == ACCESS_CODE:
        with open('banned_user.txt', 'r') as f:
            lines = f.readlines()
        with open('banned_user.txt', 'w') as f:
            for line in lines:
                if line.strip() != username:
                    f.write(line)
        flash(f"Utilisateur {username} débanni avec succès.", "admin-success")
    else:
        flash("Code d'accès incorrect.", "admin-error")

    return redirect(url_for('admin'))



# Initialisation de la base de données
init_db()

@app.template_filter()
def safe_message(message):
    # Utiliser escape pour échapper tout sauf les apostrophes et guillemets
    return message.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#x27;', "'")

@app.route('/chat')
def chat():
    username = session.get('username')  # Récupérer le pseudo de la session
    user_id = request.cookies.get('user_id')  # Récupérer l'ID de l'utilisateur depuis le cookie

    if username:
        if not user_id:  # Si l'ID n'existe pas, en créer un nouveau
            user_id = str(uuid.uuid4())  # Générer un ID unique pour l'utilisateur
            response = make_response(render_template('index.html', username=username, user_id=user_id, messages=get_messages()))
            response.set_cookie('user_id', user_id)  # Stocker l'ID dans un cookie
            print(f"{Colors.GREEN}Nouvel utilisateur connecté : {username} (ID: {user_id}){Colors.RESET}")
            return response
        else:
            messages = get_messages()
            print(f"{Colors.BLUE}Utilisateur reconnecté : {username} (ID: {user_id}){Colors.RESET}")
            return render_template('index.html', username=username, user_id=user_id, messages=messages)

    return redirect(url_for('login'))

@app.route('/politique')
def politique():
    print(f"{Colors.YELLOW}Accès à la politique de confidentialité.{Colors.RESET}")
    return render_template('politique.html')
from html import escape  # Assurez-vous d'importer cette fonction

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        code = request.form.get('code')
        if code == ACCESS_CODE:
            session['authenticated'] = True  # Marque l'utilisateur comme authentifié
            return redirect(url_for('admin'))  # Redirige vers l'administration
        else:
            return render_template('admin.html', error="Code incorrect.")

    if not session.get('authenticated'):  # Vérifie si l'utilisateur est authentifié
        return render_template('admin.html')  # Afficher le formulaire pour entrer le code

    messages = get_messages()  # Récupérer les messages pour les utilisateurs authentifiés
    return render_template('admin.html', messages=messages)

@app.route('/delete_message/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if not session.get('authenticated'):  # Vérifie si l'utilisateur est authentifié
        flash("Vous devez être authentifié pour supprimer un message.", "error")
        return redirect(url_for('admin'))  # Redirige vers l'administration

    try:
        conn = sqlite3.connect('chat.db')
        c = conn.cursor()
        c.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        flash("Message supprimé avec succès.", "success")
    except sqlite3.Error as e:
        print(f"Erreur lors de la suppression du message : {e}")
        flash("Erreur lors de la suppression du message.", "error")
    finally:
        conn.close()

    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.pop('authenticated', None)  # Retire l'authentification de la session
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for('admin'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hacher le mot de passe (utilisez bcrypt ou un autre moyen dans un projet réel)
        hashed_password = escape(password)
        
        try:
            conn = sqlite3.connect('chat.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash("Inscription réussie. Vous pouvez maintenant vous connecter.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Nom d'utilisateur déjà pris.", "error")
        except sqlite3.Error as e:
            print(f"Erreur SQLite: {e}")
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = sqlite3.connect('chat.db')
            c = conn.cursor()
            c.execute('SELECT password FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result and result[0] == escape(password):  # Vérification du mot de passe
                session['username'] = username  # Stocker le pseudo dans la session
                user_id = str(uuid.uuid4())  # Générer un ID unique pour l'utilisateur
                response = make_response(redirect(url_for('chat')))
                response.set_cookie('user_id', user_id)  # Stocker l'ID dans un cookie
                return response
            else:
                flash("Nom d'utilisateur ou mot de passe incorrect.", "login-error")  # Catégorie spécifique login
        except sqlite3.Error as e:
            print(f"Erreur SQLite: {e}")
        finally:
            conn.close()

    return render_template('login.html')

@socketio.on('message')
def handle_message(message):
    try:
        username, message_text = message.split(': ', 1)
        user_id = request.cookies.get('user_id')  # Récupérer l'ID de l'utilisateur depuis le cookie

        # Vérifier si l'utilisateur est banni
        if is_banned(username):
            print(f"{Colors.RED}Utilisateur {username} est banni et a essayé d'envoyer un message.{Colors.RESET}")
            warning_message = "Vous êtes banni et ne pouvez pas envoyer de messages."
            socketio.send(warning_message, to=request.sid)  # Envoi uniquement à cet utilisateur
            return  # Ne pas continuer le traitement du message

        # Vérification de la limite de messages
        now = datetime.datetime.now().timestamp()  # Temps actuel
        user_messages[user_id] = [timestamp for timestamp in user_messages[user_id] if now - timestamp < TIME_FRAME]  # Supprimer les anciens timestamps

        if len(user_messages[user_id]) >= MESSAGE_LIMIT:
            print(f"{Colors.RED}Utilisateur {username} (ID: {user_id}) a dépassé la limite d'envoi de messages.{Colors.RESET}")
            warning_message = "Vous ne pouvez pas envoyer plus de 2 messages par seconde."
            socketio.send(warning_message, to=request.sid)  # Envoi uniquement à cet utilisateur
            return

        # Échapper le pseudo et le message
        escaped_username = escape(username)
        escaped_message_text = escape(message_text)

        print(f"{Colors.BLUE}Message reçu : Username : {escaped_username}, Message : {escaped_message_text}, ID : {user_id}{Colors.RESET}")
        log_message(escaped_username, user_id, escaped_message_text)

        # Ajouter le timestamp actuel à la liste des messages envoyés par l'utilisateur
        user_messages[user_id].append(now)

        # Envoi du message formaté
        send(f"{escaped_username}: {escaped_message_text}", broadcast=True)
        add_message(escaped_username, escaped_message_text)

    except ValueError as e:
        print(f"{Colors.RED}Erreur lors de l'analyse du message : {e}{Colors.RESET}")



if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
    