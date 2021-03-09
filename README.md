# Email Relay

Creates disposable emails that are relayed to your real email address without exposing it.

<img src="https://user-images.githubusercontent.com/3810567/110368209-a20dae80-8040-11eb-8744-a17769943711.jpg" width="500">

## Stack

- AWS SES MTA
- AWS Lambda
- AWS S3
- Python 3.9
- Flask
- SQLite3
- Nginx


## Local Dev

- Setup AWS SES MTA

- Setup aws lambda in `src/aws-lambdas/ses_reject_mail_from_inactive_recipient`

- Create venv o project root path: `python3.9 -m venv ./venv `

- Activate venv: `source <project_root_path>/venv/bin/activate`

- Install dependencies: `pip install -r src/requirements.txt`

- Duplicate `credentials.sample.py` into `credentials.py` and fill the secrets

- Start local webserver

```bash
export FLASK_ENV=development;export FLASK_APP=<project_root_path>/src/web_app; <project_root_path>/venv/bin/flask run -h 0.0.0.0
```

- Load initial sqlite schema inside created db: `.read src/start_db.sql`

- Relaying is managed by `src/process_emails.py` 


- Routes
```

Endpoint                                Methods  Rule                                                                                                                                                         
--------------------------------------  -------  ---------------------------------------                                                                                                                      
api_create_mailbox                      POST     /api/create-mailbox                                                                                                                                          
api_create_new_user                     POST     /api/create_new_user                                                                                                                                         
api_mailbox_actions                     POST     /api/mailbox-actions                                                                                                                                         
api_request_login_link                  POST     /api/request_login_link                                                                                                                                      
api_send_user_feedback                  POST     /api/send_user_feedback                                                                                                                                      
dashboard                               GET      /dashboard                                                                                                                                                   
dashboard_mailbox                       GET      /dashboard/mailboxes/<uuid:mailbox_id>                                                                                                                       
feedback                                GET      /feedback                                                                                                                                                    
internal_api_check_if_email_is_allowed  GET      /internal_api/check_if_email_is_allowed                                                                                                                      
login                                   GET      /login                                                                                                                                                       
logout                                  GET      /logout
registration                            GET      /registration
report_errors                           POST     /api/report_errors
static                                  GET      /static/<path:filename>
```


## Crons

```

*/5 *  * * * <project_root_path>/venv/bin/python3.9  <project_root_path>/src/process_emails.py  >> <project_root_path>/logs/cron-process_emails.log
```

## Testing Nginx

```nginx

server{
	listen 80;
	server_name 127.0.0.1;

	# all static stuff will be served from here
	root <project_root_path>/src/public; 
	# folder logs needs to exist in project root
	access_log <project_root_path>/logs/nginx-access.json;
	error_log <project_root_path>/logs/nginx-error.log;
	index index.html;


	# set headers
	proxy_set_header HOST $host;
	proxy_set_header X-Real-IP $remote_addr;
	proxy_set_header X-Forwarded-Proto $scheme;
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;


	location /feedback {
		proxy_pass http://localhost:5000/feedback;
	}

	location /login {
		proxy_pass http://localhost:5000/login;
	}

	location /registration {
		proxy_pass http://localhost:5000/registration;
	}

	location /logout {
		proxy_pass http://localhost:5000/logout;
	}

	location /dashboard {
		proxy_pass http://localhost:5000/dashboard;
	}

	location /api {
		proxy_pass http://localhost:5000/api;
	}

}
```