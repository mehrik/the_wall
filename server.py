from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
from flask.ext.bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = MySQLConnector('the_wall_db')
app.secret_key = 'maricIsTired'
NAME_REGEX = re.compile(r'^[a-zA-z]{2,}$')
EMAIL_REGEX = re.compile(r'^[a-za-z0-9\.\+_-]+@[a-za-z0-9\._-]+\.[a-za-z]*$')

###################
###################
#                 #
# MODEL FUNCTIONS #
#                 #
###################
###################

def email_validate(email): 
	query = mysql.fetch("SELECT * FROM users WHERE email='{}'".format(email))
	return query

def getMessages():
	query = mysql.fetch("SELECT user_id, first_name, last_name, messages.created_at, message, messages.id FROM messages JOIN users ON users.id = messages.user_id ORDER BY messages.created_at DESC")
	return query

def getComments():
	query = mysql.fetch("SELECT comment, messages.id, first_name, last_name, comments.created_at FROM comments JOIN messages ON messages.id = comments.message_id JOIN users ON users.id = comments.user_id ORDER BY comments.created_at DESC")
	return query

def post_message(user_id, message):
	message = str(message).replace("'", "\\'")
	insert = "INSERT INTO `the_wall_db`.`messages` (`user_id`, `message`, `created_at`, `updated_at`) VALUES ('{}', '{}', NOW(), NOW())" 
	query = insert.format(user_id, message)
	print query
	mysql.run_mysql_query(query)

def post_comment(message_id, user_id, comment):
	comment = str(comment).replace("'", "\\'")
	insert = "INSERT INTO `the_wall_db`.`comments` (`message_id`, `user_id`, `comment`, `created_at`, `updated_at`) VALUES ('{}', '{}', '{}', NOW(), NOW())" 
	query = insert.format(message_id, user_id, comment)
	print query
	mysql.run_mysql_query(query)


#####################
#####################
#                   #
# MODEL CONTROLLERS #
#                   #
#####################
#####################

@app.route('/', methods=['GET'])
def index():
	return render_template('index.html')

@app.route('/create_user', methods=['POST'])
def create():
	first_name = request.form['first_name']
	last_name = request.form['last_name']
	email = request.form['email']
	email_check = email_validate(email)
	password = request.form['password']
	if password:
		pw_hash = bcrypt.generate_password_hash(password)
	error = False

	if not email or not first_name or not last_name or not password:
		flash('1 or more of the required fields have not been completed')
		error = True
	if not NAME_REGEX.match(first_name) or not NAME_REGEX.match(last_name):
		flash('Name fields must contain at least 2 characters and cannot contain any numbers or special characters')
		error = True	
	if not EMAIL_REGEX.match(email) and email:
		flash('Invalid email')
		error = True
	for user in email_check:
		if email == user['email']:
			flash('Email already exists, please use another email')
			error = True
	if len(password) < 8:
		flash('Password field must contain at least 8 characters')
		error = True
	if password != request.form['confirm']:
		flash('Passwords must match')
		error = True
	if error == True:
		return redirect('/')
	
	insertInto = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES ('{}', '{}', '{}', '{}', NOW(), NOW())"
	query = insertInto.format(first_name, last_name, email, pw_hash)
	mysql.run_mysql_query(query)

	session['email'] = email
	return redirect('/wall')

@app.route('/sign_in', methods=['POST'])
def sign_in():
	session['email'] = request.form['loginEmail']
	password = request.form['loginPassword']
	user_info = email_validate(session['email'])

	for user in user_info:
		if bcrypt.check_password_hash(user['pw_hash'], password):
			return redirect('/wall')
	flash('Email and Password did not match')
	return redirect('/')

@app.route('/wall')
def homepage():
	email = session['email']
	user_info = email_validate(email)
	first_name = user_info[0]['first_name']
	last_name = user_info[0]['last_name']
	session['user_id'] = user_info[0]['id']
	messagedb = getMessages()
	commentdb = getComments()
	print commentdb
	return render_template('/users_wall.html', first_name=first_name, last_name=last_name, messagedb=messagedb, commentdb=commentdb)

@app.route('/message', methods=['POST'])
def message():
	user_id = session['user_id']
	msg = request.form['message']
	post_message(user_id, msg)
	return redirect('/wall')

@app.route('/comment', methods=['POST'])
def comment():
	message_id = request.form['message_id']
	user_id = session['user_id']
	comment = request.form['comment']
	post_comment(message_id, user_id, comment)
	return redirect('/wall')

@app.route('/logoff')
def logoff():
	session.clear()
	flash('You have successfully logged off!')
	return redirect('/')

app.run(debug=True)