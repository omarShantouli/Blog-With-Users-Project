from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, login_manager
from flask_gravatar import Gravatar
from forms import CreatePostForm
from flask_wtf import *
from wtforms import *
from wtforms.validators import *
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

#CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class User(UserMixin , db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key= True)
    email = db.Column(db.String(250), nullable= False, unique= True)
    password = db.Column(db.String(250), nullable= False)
    name = db.Column(db.String(250), nullable= False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key= True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    #***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.String(250), nullable=False)


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

#================================================================================

class Regester_Form(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    name = StringField(label= 'Name', validators=[DataRequired()])
    submit = SubmitField(label= 'Sign Me Up')

@app.route('/register', methods= ['POST', 'GET'])
def register():
    form = Regester_Form()
    if form.validate_on_submit():
        user = User.query.filter_by(email= form.email.data).first()
        if user != None:
            flash("You've already signed up with that email, login instead.")
            return render_template("register.html", form= form)
        password = generate_password_hash(password= form.password.data, method= 'pbkdf2:sha256', salt_length= 8)
        new_user = User(
            email= form.email.data,
            password= password,
            name= form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form= form)

#================================================================================

class Login_Form(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='Let Me In!')

@app.route('/login', methods= ['GET', 'POST'])
def login():
    login_form = Login_Form()
    if login_form.validate_on_submit():
        password = login_form.password.data
        email = login_form.email.data
        user = User.query.filter_by(email= email).first()
        if user == None:
            flash('The email does not exist. Please try again.')
            return render_template('login.html', form= login_form)
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        flash('Password incorrect. Please try again.')
        return render_template('login.html', form= login_form)

    return render_template("login.html", form= login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))



class Comment_Form(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
@app.route("/post/<int:post_id>", methods= ['POST', 'GET'])
def show_post(post_id):
    form = Comment_Form()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment! ")
            return redirect(url_for('show_post', post_id= requested_post.id))
        new_comment = Comment(text= form.comment.data,
                              comment_author = current_user,
                              parent_post= requested_post,
                              )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id= requested_post.id))
    all_comments = Comment.query.filter_by(post_id= post_id).all()
    return render_template("post.html", post=requested_post, form= form, comments= all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods= ['GET', 'POST'])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods= ['POST', 'GET'])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)


