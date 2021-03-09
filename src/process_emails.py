
'''
    gist: Retrieve emails from s3; check if they belong to user mailbox and can be relayed;
        then relay to email or other integrations; after all this the email is moved to folder for emails that were processed

'''


import boto3
import sys
import requests
import datetime
import mailparser
import sqlite3
from uuid import uuid4
import jinja2
import traceback
import credentials # locally defined credentials

def telegram_send_email_relay(text, chat_id: int):

    telegram_response = requests.post(f'{credentials.TELEGRAM_BOT_API_URL}{credentials.TELEGRAM_RELAY_BOT_API_TOKEN}/sendMessage',
        data={
            "chat_id": chat_id,
            "text": text,
        }
    )
    return telegram_response

def telegram_send_error_reporting(message):

    telegram_response = requests.post(f'{credentials.TELEGRAM_BOT_API_URL}{credentials.INTERNAL_TELEGRAM_BOT_API_TOKEN}/sendMessage',
        data={
            "chat_id": credentials.INTERNAL_TELEGRAM_BOT_ADMIN_CHAT_ID,
            "text": message,
        }
    )
    return telegram_response.json()


if __name__ == '__main__':
    script_start_time = datetime.datetime.now()
    print(f'\nStarted at: { script_start_time }')
    
    s3 = boto3.client('s3', aws_access_key_id=credentials.AWS_ACCESS_KEY_ID, aws_secret_access_key=credentials.AWS_SECRET_ACCESS_KEY) 
    ses = boto3.client('ses', region_name=credentials.SES_REGION_NAME, aws_access_key_id=credentials.AWS_ACCESS_KEY_ID, aws_secret_access_key=credentials.AWS_SECRET_ACCESS_KEY)

    db = sqlite3.connect(f'{credentials.BASE_DIR}/{credentials.DATABASE_NAME}')
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    jinja_env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(f'{credentials.BASE_DIR}/templates'),
        trim_blocks=True,
        lstrip_blocks=True,
    )


    s3_bucket_items = s3.list_objects_v2(
        Bucket=credentials.S3_BUCKET, 
        Prefix=credentials.S3_BUCKET_UNPROCESSED_INBOX_KEY, 
        MaxKeys=credentials.S3_BUCKET_UNPROCESSED_INBOX_MAX_ITEMS_PER_RUN
    )

    if s3_bucket_items['ResponseMetadata']['HTTPStatusCode'] != 200 or s3_bucket_items['KeyCount'] < 1:
        print('No emails... exiting')
        sys.exit(0)

    print(f"Found {s3_bucket_items['KeyCount']} email(s)")

    for item in s3_bucket_items['Contents']:
        # we'll want to filter out files that are not emails
        folder, item_key = item['Key'].split('/')
        if bool(item_key) is False:
            continue
        
        try:
            s3_email_request = s3.get_object(Bucket=credentials.S3_BUCKET, Key=item['Key'])
            s3_email: bytes = s3_email_request['Body'].read()
            parsed_mail: mailparser.MailParser = mailparser.parse_from_bytes(s3_email)
        except Exception:
            context = {
                "what": "Error while trying retrieve & parse s3 email",
                "s3_item_id": item['Key'],
                "traceback": traceback.format_exc(),
            }

            rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
            print(rendered_error_reporting)
            telegram_send_error_reporting(rendered_error_reporting)
            continue


        email_to: tuple = parsed_mail.mail['to'][0] # name | mail address
        print(f'Email from: {parsed_mail.mail["from"][0]}')
        print(f"{email_to=}")
        
        user_mailbox = cursor.execute("""
        SELECT 
            user.id AS user_id, 
            user.email AS user_email, 
            user.telegram_user_chat_id AS user_telegram_user_chat_id, 
            user.created_at AS user_created_at, 
            mailbox.id AS mailbox_id, 
            mailbox.is_blocked AS mailbox_is_blocked, 
            mailbox.generated_email AS mailbox_generated_email,
            mailbox.mailbox_for AS mailbox_for,
            mailbox.relay_to_mail AS mailbox_relay_to_mail,
            mailbox.relay_to_telegram AS mailbox_relay_to_telegram,
            mailbox.created_at AS mailbox_created_at
        FROM mailboxes AS mailbox 
        INNER JOIN users AS user ON mailbox.user_id = user.id 
        WHERE mailbox.generated_email = ? 
        LIMIT 1;
         """, [email_to[1]]).fetchone()

        if user_mailbox is not None:

            # mailbox validation
            if bool(user_mailbox['mailbox_is_blocked']) is True:
                print('This mailbox is blocked... stopping relay!')
                s3.delete_object(Bucket=credentials.S3_BUCKET, Key=item['Key'])
                print('email deleted!')
                continue
        else:
            # TODO: manage something here yo!
            raise Exception('No mailboxes')

        ## Process relay
        email_is_sent = False
        telegram_is_sent = False
        telegram_relay_fail_reason = None
        email_relayed_at = None


        # create email db entry
        try:
            cursor.execute("""
                INSERT INTO  mails(
                    id, 
                    mailbox_id,
                    s3_file_id,
                    received_at,
                    relayed_at, 
                    virus_verdict, 
                    spam_verdict, 
                    email_from, 
                    created_at, 
                    updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ? , ?)
                """, (
                        mail_id := str(uuid4()),
                        user_mailbox['mailbox_id'],
                        s3_item_key := item['Key'].replace(credentials.S3_BUCKET_UNPROCESSED_INBOX_KEY, ''),
                        str(parsed_mail.mail['date']), # received_at
                        str(datetime.datetime.now()), # relayed_at
                        parsed_mail.mail['x-ses-virus-verdict'],
                        parsed_mail.mail['x-ses-spam-verdict'],
                        parsed_mail.mail['from'][0][1],
                        str(datetime.datetime.now()), # created_at
                        str(datetime.datetime.now()) # updated_at
                    )
            )
            db.commit()
        except sqlite3.IntegrityError:
            print('Failed to create email item since it already exists. moving along...')
            # if the mail already exists in the db let's get that entry by its s3_key and use for further rety logic
            mail_id = cursor.execute("SELECT id FROM mails WHERE s3_file_id = ? AND mailbox_id = ? LIMIT 1;", [s3_item_key, user_mailbox['mailbox_id']]).fetchone()['id']
        except Exception:
            context = {
                "what": "Error while trying to create email db entry",
                "s3_item_id": item['Key'],
                "traceback": traceback.format_exc(),
            }

            rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
            print(rendered_error_reporting)
            telegram_send_error_reporting(rendered_error_reporting)
            continue

        # mail entry in db
        mail_item = cursor.execute("SELECT * FROM mails WHERE id = ? LIMIT 1;", [mail_id]).fetchone()


        if bool(user_mailbox['mailbox_relay_to_mail']) is True and bool(mail_item['relayed_to_email']) is False:

            mailbox_dashboard_url = f'{credentials.EXTERNAL_URL}/dashboard/mailboxes/{user_mailbox["mailbox_id"]}'

            try:
                rendered_relay_email = jinja_env.get_template('emails/relay_email_html').render(
                    user_mailbox=user_mailbox,
                    parsed_mail=parsed_mail,
                    our_email_sender_address=credentials.OUR_SENDER_EMAIL_ADDRESS,
                    mailbox_dashboard_url=mailbox_dashboard_url,
                )
            except Exception:
                context = {
                    "what": "Error while trying to render the relay email template",
                    "s3_item_id": item['Key'],
                    "traceback": traceback.format_exc(),
                }

                rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
                print(rendered_error_reporting)
                telegram_send_error_reporting(rendered_error_reporting)
                continue

            try:
                send_email_request = ses.send_raw_email(Source=credentials.OUR_SENDER_EMAIL_ADDRESS, RawMessage={'Data': rendered_relay_email.encode()})
            except Exception:
                context = {
                    "what": "Error while trying to relay email to user email",
                    "s3_item_id": item['Key'],
                    "traceback": traceback.format_exc(),
                }

                rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
                print(rendered_error_reporting)
                telegram_send_error_reporting(rendered_error_reporting)
                continue

            email_relayed_at = datetime.datetime.now()
            print(f'{send_email_request=}', end='\n\n')

            email_is_sent: bool = send_email_request['ResponseMetadata']['HTTPStatusCode'] == 200
            
            if email_is_sent:
                cursor.execute("UPDATE mails SET relayed_to_email = ? WHERE id = ?", ([1, mail_id])) 
                db.commit()


        if bool(user_mailbox['mailbox_relay_to_telegram']) is True and user_mailbox['user_telegram_user_chat_id'] is not None and bool(mail_item['relayed_to_telegram']) is False:

            try:
                rendered_relay_email = jinja_env.get_template('telegram/relay_email.txt').render(
                    user_mailbox=user_mailbox,
                    parsed_mail=parsed_mail,
                    our_email_sender_address=credentials.OUR_SENDER_EMAIL_ADDRESS
                )
            except Exception:
                context = {
                    "what": "Error while trying to parse telegram relay template",
                    "s3_item_id": item['Key'],
                    "traceback": traceback.format_exc(),
                }

                rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
                print(rendered_error_reporting)
                telegram_send_error_reporting(rendered_error_reporting)

            try:
                telegram_request = telegram_send_email_relay(rendered_relay_email, user_mailbox['user_telegram_user_chat_id'])
                telegram_request.raise_for_status()
            except Exception:
                context = {
                    "what": "Error while trying to send telegram email relay",
                    "s3_item_id": item['Key'],
                    "description": telegram_request.json().get('description'),
                    "traceback": traceback.format_exc()
                }

                rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
                print(rendered_error_reporting)
                telegram_send_error_reporting(rendered_error_reporting)

            telegram_response = telegram_request.json()
            if telegram_response['ok'] is False:
                telegram_relay_fail_reason = telegram_response.get('description')

            print(f'{telegram_response=}', end='\n\n')
            telegram_is_sent = telegram_response['ok'] is True

            if telegram_is_sent:
                cursor.execute("UPDATE mails SET relayed_to_telegram = ? WHERE id = ?", ([1, mail_id])) 
                db.commit()


       
        # let's move email to processed email folder 
        # TODO: check if S3_BUCKET_UNPROCESSED_INBOX_KEY folder is being deleted
        try:
            print('done! copying mail to processed folder and deleting current one..')
            s3.copy({"Bucket": credentials.S3_BUCKET, "Key": item['Key']}, credentials.S3_BUCKET, f"{credentials.S3_BUCKET_PROCESSED_INBOX_KEY}{s3_item_key}")
            s3.delete_object(Bucket=credentials.S3_BUCKET, Key=item['Key'])
        except Exception:
            context = {
                "what": "Error while trying to move the email to the processed emails folder in s3.",
                "s3_item_id": item['Key'],
                "traceback": traceback.format_exc(),
            }

            rendered_error_reporting = jinja_env.get_template('telegram/error_reporting_process_emails').render(**context)
            print(rendered_error_reporting)
            telegram_send_error_reporting(rendered_error_reporting)

    db.close()
    print(f'Done. Duration {datetime.datetime.now() - script_start_time}')


