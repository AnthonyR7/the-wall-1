from flask import Flask, render_template, request, redirect, flash, session
# mysqlconnector
from mysqlconnection import MySQLConnector
#regex
import re
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
#found a name regex from online
name_regex = re.compile(r'^[A-Z][-a-zA-Z]+$')
#import bcrypt
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "mysecretkey"

# connect and store connection in mysql
mysql = MySQLConnector(app, 'the_wall')

# Moving my validations to a function that can be called for login and registration. Not working at the moment
def validate(email, first_name, last_name, password):
    if email and not email_regex.match(request.form['email']):
        flash("Invalid Email Address!")
    if first_name and not name_regex.match(request.form['first_name']):
        flash("Invalid first name")
    if last_name and not name_regex.match(request.form['last_name']):
        flash("Invalid last name")
    if password and len(password) < 8:
        flash("Password must be over 8 characters")

# Index page with registration and login forms
@app.route('/')
def index():
    # checks to see if there is a session for request
    if 'user' in session:
        return redirect('/wall')
    else:
        return render_template('/index.html')

# Handles login of user
@app.route('/login', methods=['POST'])
def login():
    # Makes sure email and password were input
    if request.form['email'] and request.form['pw']:
        query = "SELECT * FROM users WHERE email=:email"
        data = {
            'email': request.form['email']
        }
        # checks of user matches in db
        if len(mysql.query_db(query, data)) > 0:
            user = mysql.query_db(query, data)[0]
            print("user: {}".format(user))
            if bcrypt.check_password_hash(user['pw_hash'], request.form['pw']):
                # Adds user to session
                session['user'] = user
                flash("Logged in Successfully")
                return redirect('/wall')
    flash("Incorrect username or password")
    return redirect('/')

# Handles logout of user
@app.route('/logout', methods=['POST'])
def logged_out():
    session.pop('user', None)
    return redirect('/')

# Handles Registration
@app.route('/register', methods=['POST'])
def registration():
    #use of errors counter to check if any flashes are added
    errors = 0
    # Checks for using an email that's already been used
    query = "SELECT email FROM users WHERE email=:email"
    data = {
        'email': request.form['email']
    }
    registered_users = mysql.query_db(query, data)
    print(registered_users)
    if registered_users:
        errors += 1
        flash("Email has already been used")
    #validates that there is an email present
    if not request.form['email']:
        errors += 1
        flash("Please add an email")
    if not name_regex.match(request.form['first_name']) or not name_regex.match(request.form['last_name']):
        errors += 1
        flash("Invalid first or last name")
    if not email_regex.match(request.form['email']):
        errors += 1
        flash("Invalid Email Address!")
    if len(request.form['pw']) < 8:
        errors += 1
        flash("Password must be greater than 8 characters")
    if request.form['pw'] != request.form['pw_confirmation']:
        errors += 1
        flash("Password must match password confirmation")
    # Want to find a way to check if flash has messages in it. Substituting with a error counter for now
    if errors == 0:
        flash("New user successfully registered")
        pw_hash = bcrypt.generate_password_hash(request.form['pw'])
        query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, Now(), Now());"
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'pw_hash': pw_hash
        }
        mysql.query_db(query, data)
        query = "SELECT * FROM users WHERE email=:email AND first_name=:first_name AND last_name=:last_name"
        user = mysql.query_db(query, data)[0]
        # adds user to session
        session['user'] = user
        return redirect('/wall')
    return redirect('/')

# The Wall
@app.route('/wall')
def wall():
    print(session['user'])
    if 'user' in session:
        query = "SELECT first_name, last_name, message_text, DATE_FORMAT(messages.created_at, '%M %D %Y %H:%i') AS created_at, messages.id, user_id FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
        message_list = mysql.query_db(query)
        #print(message_list)
        query = "SELECT first_name, last_name, comment_text, DATE_FORMAT(comments.created_at, '%M %D %Y %H:%i') AS created_at, message_id FROM comments JOIN users ON comments.user_id = users.id ORDER BY comments.created_at"
        comment_list = mysql.query_db(query)
        #print(comment_list)
        return render_template('/wall.html', message_list = message_list, comment_list = comment_list)
    else:
        flash("You are not logged in")
        return redirect('/')

@app.route('/wall/message', methods=['POST'])
def add_message():
    message_text = request.form['message']
    query = "INSERT INTO messages (message_text, created_at, updated_at, user_id) VALUES (:message_text, Now(), Now(), :user_id)"
    data = {
        'message_text': message_text,
        'user_id': session['user']['id']
    }
    mysql.query_db(query, data)
    return redirect('/wall')
@app.route('/wall/comment/<message_id>', methods=['POST'])
def add_comment(message_id):
    query = "INSERT INTO comments (comment_text, created_at, updated_at, user_id, message_id) VALUES (:comment_text, Now(), Now(), :user_id, :message_id)"
    data = {
        'comment_text': request.form['comment'],
        'user_id': session['user']['id'],
        'message_id': message_id
    }
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/wall/message/delete/<id>')
def delete_comment(id):
    del_comments_query = "DELETE FROM comments WHERE message_id = :id"
    data = {
        'id': id
    }
    mysql.query_db(del_comments_query, data)
    del_message_query = "DELETE FROM messages WHERE id = :id"
    mysql.query_db(del_message_query, data)
    return redirect('/wall')

app.run(debug=True)
