import datetime
from flask import Flask, render_template, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user , login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
import random as r


UPLOAD_FOLDER = 'static/files'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3'}
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
bcrypt= Bcrypt(app)
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    liked_post = db.relationship("Post", secondary="like", backref="liked_by")
    posts = db.relationship("Post", backref="author", cascade="all, delete-orphan")
    coments = db.relationship("coment", backref="author", cascade="all, delete-orphan")

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    like_count= db.Column(db.Integer, default=0)
    img = db.Column(db.String(50), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    coments = db.relationship("coment", backref="post", cascade="all, delete-orphan")

class Like(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), primary_key=True)

class Follow(db.Model):
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now())

class coment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(20), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], 
                render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], 
                render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



@app.route('/new_post', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        try:
            print("//"*10)
            file = request.files['image']
            if (file and allowed_file(file.filename)) and request.form['content'] != '':
                filename = secure_filename(file.filename)
                filename = filename.split('.')[0] + str(current_user.id) + '_' + str(r.random()).split('.')[1]+ '.' + filename.split('.')[1]
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                post = Post(content=request.form['content'], img=filename, author_id=current_user.id)
                db.session.add(post)
                db.session.commit()
                return redirect(url_for('posts'))
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = filename.split('.')[0] + str(current_user.id) + '_' + str(r.random()).split('.')[1]+ '.' + filename.split('.')[1]
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return redirect(url_for('posts'))
            if request.form['content'] != '':
                post = Post(content=request.form['content'],img='', author_id=current_user.id)
                db.session.add(post)
                db.session.commit()
                return redirect(url_for('posts'))
            else:
                return redirect(url_for('posts'))
        except:
                return redirect(url_for('posts'))


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    posts = Post.query.all()
    users = User.query.all()
    comments = coment.query.all()
    return render_template('posts.html', posts=posts, users=users, comments=comments)

@app.route('/delete_post/<int:id>')
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)
    filename= post.img
    if filename !='':
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    db.session.delete(post)
    db.session.commit()

    return redirect(url_for('posts'))

@app.route('/post_follow', methods=['GET', 'POST'])
@login_required
def post_follow():
    f =Follow.query.filter_by(follower_id=current_user.id).all()
    posts = Post.query.filter_by(author_id = (Follow.followed_id)).all()
    users = User.query.all()
    return render_template('Followed.html', posts=posts, users=users)


@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return redirect(url_for('posts'))
    if user.username == current_user.username:
        return redirect(url_for('posts'))
    try:
        follow = Follow(follower_id=current_user.id, followed_id=user.id)
        db.session.add(follow)
        db.session.commit()
        return redirect(url_for('posts'))
    except:
        return redirect(url_for('posts'))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return redirect(url_for('posts'))
    if user.username == current_user.username:
        return redirect(url_for('posts'))
    try:
        follow = Follow.query.filter_by(follower_id=current_user.id, followed_id=user.id).first()
        db.session.delete(follow)
        db.session.commit()
        return redirect(url_for('posts'))
    except:
        return redirect(url_for('posts'))

@app.route('/base', methods=['GET', 'POST'])
def base():
    return render_template('base.html')

##########################
@app.route('/new_comment/<post_id>', methods=['GET', 'POST'])
@login_required
def new_comment(post_id):
    if request.method == 'POST':
        comment_content = request.form['coment']
        new_comment = coment(content=comment_content, author_id=current_user.id, post_id=post_id, author_name=current_user.username)

        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('posts'))
    else:
        return redirect(url_for('posts'))


@app.route('/like/<post_id>', methods=['GET', 'POST'])
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    new_like = Like(user_id=current_user.id, post_id=post_id)
    if post:
        if Like.query.filter_by(user_id=current_user.id, post_id=post_id).first():
            post.like_count = post.like_count - 1
            db.session.commit()
            Like.query.filter_by(user_id=current_user.id, post_id=post_id).delete()
            db.session.commit()
            return redirect(url_for('posts'))
        else:
            db.session.add(new_like)
            db.session.commit()
            post.like_count = post.like_count + 1
            db.session.commit()
            return redirect(url_for('posts'))
    else:
        return redirect(url_for('posts'))

@app.route('/profile/<int:id>', methods=['GET', 'POST'])
@login_required
def profile(id):
    posts = Post.query.filter_by(author_id=id).all()
    return render_template('profile.html', posts=posts)


if __name__ == '__main__':
    app.run(debug=True)