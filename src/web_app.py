from flask import Flask, render_template, request, session, g, redirect, url_for, abort
from http import HTTPStatus
import requests
import uuid
import secrets
import sqlite3
import datetime
import functools
import boto3
from . import credentials  # locally defined credentials

app = Flask(__name__)


app.config.update(
    SECRET_KEY=credentials.SECRET_KEY,
    PERMANENT_SESSION_LIFETIME=credentials.LOGIN_SESSION_EXPIRATION_TIME,
)

ses = boto3.client(
    'ses', 
    region_name=credentials.SES_REGION_NAME, 
    aws_access_key_id=credentials.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=credentials.AWS_SECRET_ACCESS_KEY
)

def generate_random_email() -> str:
    return f'{uuid.uuid4().hex[:6]}@segrob.studio'

def telegram_send_internal_text_msg(text) -> requests.Response:

    telegram_response = requests.post(
        f'{credentials.TELEGRAM_BOT_API_URL}{credentials.INTERNAL_TELEGRAM_BOT_API_TOKEN}/sendMessage',
        data={
            "chat_id": credentials.INTERNAL_TELEGRAM_BOT_ADMIN_CHAT_ID,
            "text": text
        }
    )
    return telegram_response


def get_db() -> sqlite3.Connection:
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(f'{credentials.BASE_DIR}/{credentials.DATABASE_NAME}')
    db.row_factory = sqlite3.Row
    return db


def login_required(_func=None, *, is_api=False):
    ''' 
        Decorator to enforce login for web or api requests.

        For api request we need to pass is_api=True
    '''
    def decorator_login_required(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if 'login_token' in session:
                return func(*args, **kwargs)
            else:
                if is_api is True:
                    return ({"error": "authorization required!"}, HTTPStatus.UNAUTHORIZED)
                else:
                    return redirect(url_for('login'), code=HTTPStatus.UNAUTHORIZED)
        return wrapper

    if _func is None:  # a marker. it'll be None if the decorator was called with no arguments else it'll pass along the decorated funtion
        return decorator_login_required
    else:
        return decorator_login_required(_func)


def is_user_logged_in() -> bool:
    return 'login_token' in session


@app.before_request
def before_request():
    print(request, request.headers)

@app.after_request
def after_request(response):
    print(response, response.headers)
    return response


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('login_token', None)
    return redirect(url_for('login'))


@app.route('/login', methods=['GET'])
def login():
    ''' Shows the login page or authenticates the user by the login_token sent to the user email '''

    if is_user_logged_in():
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    user_email = request.args.get('user_email')
    login_token = request.args.get('login_token')

    if login_token is not None and request.method == 'GET':
        user = cursor.execute("SELECT * FROM users WHERE login_token = ? AND email = ?", [login_token, user_email]).fetchone()

        if user is not None:
            # expiration time for the user session
            session.permanent = True
            session['login_token'] = user['login_token']
            session['user_id'] = user['id']

            return redirect(url_for('dashboard'))
        else:
            error = 'Failed to login. Try again'
            return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():

    db = get_db()
    cursor = db.cursor()

    mailboxes = cursor.execute("""
        SELECT * 
        FROM mailboxes 
        WHERE user_id = ? 
        ORDER BY created_at 
        DESC;
        """, [session['user_id']]).fetchall()
    return render_template('dashboard.html', mailboxes=mailboxes)

@app.route('/dashboard/mailboxes/<uuid:mailbox_id>')
@login_required
def dashboard_mailbox(mailbox_id: uuid.uuid4):

    db = get_db()
    cursor = db.cursor()

    mailbox = cursor.execute("""
        SELECT * 
        FROM mailboxes 
        WHERE user_id = ?
        AND id = ?
        """, [session['user_id'], str(mailbox_id)]).fetchone()

    if mailbox is None:
        return abort(HTTPStatus.NOT_FOUND)

    return render_template('manage_mailbox.html', mailbox=mailbox)


@app.route('/registration', methods=['GET'])
def registration():
    if is_user_logged_in():
        return redirect(url_for('dashboard'))
      

    return render_template('register_user.html')


@app.route('/feedback', methods=['GET'])
def feedback():
    return render_template('feedback.html')

@app.route('/api/create-mailbox', methods=['POST'])
@login_required(is_api=True)
def api_create_mailbox():

    db = get_db()
    cursor = db.cursor()

    new_mailbox_for = request.form['new_mailbox_for']

    cursor.execute("""
     INSERT INTO mailboxes(id, user_id, mailbox_for, generated_email, created_at, updated_at) 
     VALUES(?, ?, ?, ?, ?, ?)
    """, (
            mailbox_id := str(uuid.uuid4()),
            session['user_id'],
            new_mailbox_for,
            generate_random_email(),
            str(datetime.datetime.now()),
            str(datetime.datetime.now())
        )
    )

    db.commit()

    created_mailbox = cursor.execute('select * from mailboxes where id = ?', [mailbox_id]).fetchone()

    if created_mailbox is not None:
        return (dict(created_mailbox), HTTPStatus.CREATED)
    else:
        return ({'error': 'something went wrong '}, HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route('/api/mailbox-actions', methods=['POST'])
@login_required(is_api=True)
def api_mailbox_actions():

    db = get_db()
    cursor = db.cursor()

    params = request.get_json(True)

    action = params['action']
    mailbox_id = params['mailbox_id']
    payload = {}

    if action == 'block':
        payload = {
            'is_blocked': True
        }

    elif action == 'unblock':
        payload = {
            'is_blocked': False
        }

    try:
        cursor.execute("UPDATE mailboxes SET is_blocked = ? WHERE id = ?", ([int(payload['is_blocked']), mailbox_id]))
    except Exception:
        raise
        return ({'error': 'something went wrong '}, HTTPStatus.INTERNAL_SERVER_ERROR)

    db.commit()

    return (payload, HTTPStatus.OK)


@app.route('/api/send_user_feedback', methods=['POST'])
def api_send_user_feedback():

    user_email = request.form['feedback_email']
    user_message = request.form['feedback_message']

    context = {
        'user_email': user_email,
        'user_message': user_message
    }

    rendered_template = render_template('telegram/user_feedback.txt', **context)

    telegram_response = telegram_send_internal_text_msg(rendered_template)

    if telegram_response.ok:
        return ("feedback sent", HTTPStatus.OK)
    else:
        print(f'telegram_response={telegram_response.text}')
        return ('feedback not sent', HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route('/api/request_login_link', methods=['POST'])
def api_request_login_link():
    ''' The user requests a login link that will be sent to his email if the account exists '''

    db = get_db()
    cursor = db.cursor()

    user_email = request.form['email']

    user = cursor.execute("SELECT * FROM users WHERE email = ? LIMIT 1", [user_email]).fetchone()

    if user is not None:
        login_url = url_for('login', login_token=user['login_token'], user_email=user['email'], _external=True)

        # create email with link to login
        user_login_email_template = render_template('/emails/user_login_link_request_html', login_url=login_url)

        print(f'{user_login_email_template}')

        send_email_request = ses.send_email(
            Source=credentials.OUR_SENDER_EMAIL_ADDRESS,
            Destination={"ToAddresses": [user_email]},
            Message={
                "Subject": {"Data": "Login link", "Charset": ""},
                "Body": {"Html": {"Data": user_login_email_template, "Charset": "UTF-8"}}
            }
        )

        return ('Check your email', HTTPStatus.OK)
    else:
        return ({"error": "Account doesn't exist. Create your account"}, HTTPStatus.NOT_FOUND)


@app.route('/api/create_new_user', methods=['POST'])
def api_create_new_user():

    db = get_db()
    cursor = db.cursor()

    user_email = request.form['email']

    user_login_token = secrets.token_urlsafe(50)

    try:
        cursor.execute("""
            INSERT INTO users(id, email, login_token, created_at, updated_at) 
            VALUES(?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), user_email, user_login_token, str(datetime.datetime.now()), str(datetime.datetime.now()))
        )
    except sqlite3.IntegrityError:
        return ({"error": "Email already in use"}, HTTPStatus.CONFLICT)

    db.commit()

    login_url = url_for('login', login_token=user_login_token, user_email=user_email, _external=True)

    # create email with link to login
    new_user_email_template = render_template('/emails/new_user_registration_html', login_url=login_url)

    print(f'{new_user_email_template=}')

    # TODO: improvement: make it async
    send_email_request = ses.send_email(
        Source=credentials.OUR_SENDER_EMAIL_ADDRESS,
        Destination={"ToAddresses": [user_email]},
        Message={
            "Subject": {"Data": "New account", "Charset": ""},
            "Body": {"Html": {"Data": new_user_email_template, "Charset": "UTF-8"}}
        }
    )

    return ('ok', HTTPStatus.CREATED)


@app.route('/api/report_errors', methods=['POST'])
def report_errors():
    context = request.get_json(True)
    context["error_origin"] = 'Front-End'

    rendered_template = render_template('/telegram/error_reporting.txt', **context)

    telegram_request = telegram_send_internal_text_msg(rendered_template)

    if telegram_request.ok:
        return ("error reported.", HTTPStatus.OK)
    else:
        print(f'telegram_request={telegram_request.text}')
        return ('failed to send error report', HTTPStatus.INTERNAL_SERVER_ERROR)


@app.route('/internal_api/check_if_email_is_allowed', methods=['GET'])
def internal_api_check_if_email_is_allowed():
    ''' 
        Used by AWS lambda function to decide whether to let the email in or not.
    '''

    destination_email = request.args.get('destination_email')

    db = get_db()
    cursor = db.cursor()

    mailbox = cursor.execute("""
        SELECT id, is_blocked
        FROM mailboxes 
        WHERE generated_email = ? ;
        """, [destination_email]).fetchone()

    if mailbox is not None:
        return (dict(mailbox), HTTPStatus.OK)
    else:
        return ({"error": "mailbox not found!"}, HTTPStatus.NOT_FOUND)


