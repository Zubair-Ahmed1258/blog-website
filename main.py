from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.orm import relationship
from flask_gravatar import Gravatar
import smtplib
import os

OWN_EMAIL = "zubair1999on@gmail.com"
OWN_PASSWORD = "humami1999"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=50,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

new_date = date.today().strftime("%B %d, %Y")

login_manager = LoginManager()
login_manager.init_app(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///newPosts.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CONFIGURE TABLE

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    comments = relationship("Comment", back_populates="author")
    posts = relationship("BlogPost", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments_table"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    name = StringField('User Name', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class CommentForm(FlaskForm):
    comment_box = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField('Submit Comment')

# @app.before_request
# def before_request():
#     g.user = current_user

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


def login_require(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated is False:
            flash('You need to login or register to comment!')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

#costom admin_only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            abort(403, description='You are not authorized for this Page request it is for admin only!')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def get_all_posts():
    logged_in = current_user.is_authenticated
    all_posts = db.session.query(BlogPost).all()
    return render_template("index.html", response=all_posts, logged_in=logged_in, current_user=current_user)


@app.route("/post/<int:index>", methods=['GET', 'POST'])
def show_post(index):
    form = CommentForm()
    logged_in = current_user.is_authenticated
    post = BlogPost.query.get(index)
    if request.method == 'POST':
        form.validate_on_submit()
        if current_user.is_authenticated is False:
            flash('You need to login or register to comment!')
            return redirect(url_for('login', next=request.url))
        else:
            new_entry = Comment(author_id=current_user.id, post_id=post.id, text=form.comment_box.data)
            db.session.add(new_entry)
            db.session.commit()
    return render_template("post.html", post=post, new_date=new_date, logged_in=logged_in, current_user=current_user, gravatar=gravatar, form=form)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def make_post():
    logged_in = current_user.is_authenticated
    text = 'New Post'
    form = CreatePostForm()
    if request.method == 'POST':
        form.validate_on_submit()
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            author_id=current_user.id,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, text=text, logged_in=logged_in)


@app.route('/edit-post/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(id):
    text = 'Edit Post'
    logged_in = current_user.is_authenticated
    post = BlogPost.query.get(id)
    post_date = post.date
    form = CreatePostForm(title=post.title,
                          subtitle=post.subtitle,
                          img_url=post.img_url,
                          author=post.author,
                          body=post.body)
    if request.method == 'POST':
        form.validate_on_submit()
        editing_post = BlogPost.query.get(id)
        editing_post.title = form.title.data
        editing_post.subtitle = form.subtitle.data
        editing_post.body = form.body.data
        editing_post.img_url = form.img_url.data
        editing_post.author = form.author.data
        editing_post.date = post_date
        db.session.commit()
        return redirect(url_for(f'show_post', index=id))
    return render_template('make-post.html', form=form, text=text, logged_in=logged_in)


@app.route('/delete')
@admin_only
def delete():
    post_id = request.args.get('id')
    post = BlogPost.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    logged_in = current_user.is_authenticated
    return render_template("about.html", logged_in=logged_in)



@app.route("/contact", methods=["GET", "POST"])
def contact():
    logged_in = current_user.is_authenticated 
    if request.method == "POST":
        data = request.form
        data = request.form
        send_email(data["name"], data["email"], data["phone"], data["message"])
        return render_template("contact.html", msg_sent=True, logged_in=logged_in)
    return render_template("contact.html", msg_sent=False, logged_in=logged_in)


def send_email(name, email, phone, message):
    email_message = f"Subject:New Message\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage:{message}"
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(OWN_EMAIL, OWN_PASSWORD)
        connection.sendmail(OWN_EMAIL, OWN_EMAIL, email_message)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = RegisterForm()
    if request.method == 'POST':
        form.validate_on_submit()
        user_email = User.query.filter_by(email=form.email.data).first()
        if user_email == None:
            flash('Please check your Email!')
        else:
            un_hashed_password = check_password_hash(user_email.password, form.password.data)
            if un_hashed_password == False:
                flash('Invalid Passcode')
            else:
                login_user(load_user(user_email.id))
                return redirect(url_for('get_all_posts'))
            return url_for('about', id=1)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        form.validate_on_submit()
        user_exist = User.query.filter_by(email=form.email.data).first()
        if user_exist:
            flash('User already exist! Please Try to Log In.')
        else:
            hash_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
            add_entry = User(email=form.email.data, password=hash_password, name=form.name.data)
            db.session.add(add_entry)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
