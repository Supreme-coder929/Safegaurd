import sqlite3
from flask import (
	Flask, 
	session,
	request,
	render_template
)
import hashlib
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)
app.config["SECRET_KEY"] = "test"

limiter = Limiter(
	get_remote_address, 
	app=app,
	default_limits=["500 per day", "50 per hour"],
	storage_uri="memory://",
	)

def password_check(value):
	parsed_word = list(value)

	# All must be True
	strong_length = False
	one_upper = False
	one_lower = False
	one_num = False

	try:
		if len(value) > 8:
			strong_length = True

		if [True for x in parsed_word if x.isupper()] and [True for x in parsed_word if x.islower()] and [True for x in parsed_word if x.isnumeric()]:
			one_upper = True
			one_lower = True
			one_num = True

	except IndexError:
		pass

	if all([strong_length, one_upper, one_lower, one_num]):
		return True
	else:
		return False



def convert_to_md5(value):
	md5_hashed_value = hashlib.md5(value.encode()).hexdigest()
	return md5_hashed_value

def check_session(value):
	if "session_key" in session:
		c = sqlite3.connect("user_db.sqlite")
		con = c.cursor()
		query = f"select email,password,encoded_key from user_db where encoded_key='{value}'"

		con.execute(query)
		data = con.fetchone()

		if data is None:
			return False
		else:
			return data[0], True
		
	else:
		return False


@app.route("/", methods=["GET", "POST"])
def home():
	return render_template("home.html")


@app.route("/sign_up", methods=["GET", "POST"])
@limiter.limit("50 per hour", methods=["POST"], error_message="You have sent too many POST requests please try again later.")
def sign_up():
	if request.method == "POST":
		email = request.form.get("email_name")
		passwd = request.form.get("password")

		if not password_check(passwd):
			return render_template("sign_up.html", output="Weak Password (Try Again)")
		else:
			pass

		hashed_value = convert_to_md5(passwd)


		s = sqlite3.connect("user_db.sqlite")
		query = f"insert into user_db(email, password, encoded_key) values ('{email}', '{hashed_value}', '{secrets.token_hex(8)}')"

		s.execute(query)
		s.commit()
		s.close()

		return "<script>alert('Succesfully signed up');window.location.href = '/login'</script>"

	return render_template("sign_up.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("50 per hour", methods=["POST"], error_message="You have sent too many POST requests please try again later.")
def login():
	if request.method == "POST":
		email = request.form.get("email_name")
		passwd = request.form.get("password")

		hashed_passwd = convert_to_md5(passwd)

		s = sqlite3.connect("user_db.sqlite")
		con = s.cursor()
		query = f"select email,password,encoded_key from user_db where email='{email}' and password='{hashed_passwd}'"


		con.execute(query)
		data = con.fetchone()
		

		if data is None:
			return render_template("login.html", output="Invalid Credentials")
		else:
			session["session_key"] = data[2]
			return "<script>alert('Successfully logged in');window.location.href = '/logged_in'</script>"

	return render_template("login.html")


@app.route("/logged_in", methods=["GET", "POST"])
@limiter.exempt
def logged_in():
	try:
		email, validated = check_session(session["session_key"])
		if validated:
			return render_template("logged_in.html", email_user=email, ses_key=session["session_key"])
	except:
		return "Unauthorized Request"





if __name__ == "__main__":
	app.run(debug=True, port=9999, host="127.0.0.1")


