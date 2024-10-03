from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] ="4374f97ecdbe53b59160b76c9b67945a5cb0f61569d5c72a11dcee68610e353b"



db = SQLAlchemy(app)
migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#Route home
@app.route('/')
def home():
    return "BOnjour"


#route inscription

@app.route('/inscription', methods=['GET', 'POST'])
def inscription():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
    
        exist = User.query.filter_by(username=username).first()
        if exist:
            flash("Le nom d'utilisateur existe déja, Veuillez en choisir un autre")
            return redirect(url_for('inscription'))
    
        mot_de_passe_sécurisé = generate_password_hash(password)
        new_user = User(username=username, password=mot_de_passe_sécurisé)
        db.session.add(new_user)
        db.session.commit()

        flash("Inscription validé, Vous pouvez vus connecter")
        return redirect(url_for('login'))
    return render_template('inscription.html')




#routeconnexion

@app.route('/login' ,methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return "Connecté avec succes"
        else:
            flash("Nom utilisateur ou mot de passe incorrect")
    return render_template('login.html')


#routedeconnexion

@app.route('/logout')
def logout():
    flash("Déconnecté réussie")
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)

