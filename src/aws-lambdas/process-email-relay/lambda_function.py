import os
import json
import boto3
import requests
from urllib.parse import unquote
from datetime import datetime
import mailparser

emails_source = os.environ['EMAILS_SOURCE']
api_url = os.environ['API_URL']
telegram_api = os.environ['TELEGRAM_API']

s3 = boto3.client('s3')
s3_bucket = 'segrob-ses-testing'

ses = boto3.client('ses', region_name='us-east-1')


def telegram_send_msg(text: list, chat_id: int):

    telegram_request = requests.post(f'https://api.telegram.org/{telegram_api}/sendMessage',
        data={
            "chat_id": chat_id,
            "text": text
        }
    )
    return telegram_request.json()


def lambda_handler(event, context):
  
    ## extract mail info from ses event
    
    ses_event = event['Records'][0]['ses']
    
    ses_mail_source = ses_event['mail']['source']
    print(f'{ses_mail_source=}')
    
    ses_mail_destination = ses_event['mail']['destination'][0]
    print(f'{ses_mail_destination=}')
    
    ses_mail_header_date =  ses_event['mail']['commonHeaders']['date']
    print(f'{ses_mail_header_date=}')
    
    ses_mail_header_from = ses_event['mail']['commonHeaders']['from'][0]
    print(f'{ses_mail_header_from=}')
    
    ses_mail_header_subject = ses_event['mail']['commonHeaders']['subject']
    print(f'{ses_mail_header_subject=}')
    
    ses_mail_s3_id = ses_event['mail']['messageId']
    print(f'{ses_mail_s3_id=}')
    
    ses_mail_spf_verdict = ses_event['receipt'].get('spfVerdict').get('status')
    print(f'{ses_mail_spf_verdict=}')
    
    ses_mail_dkim_verdict = ses_event['receipt'].get('dkimVerdict').get('status')
    print(f'{ses_mail_dkim_verdict=}')
    
    ses_mail_spam_verdict = ses_event['receipt'].get('spamVerdict').get('status')
    print(f'{ses_mail_spam_verdict=}')
    
    ses_mail_virus_verdict = ses_event['receipt'].get('virusVerdict').get('status')
    print(f'{ses_mail_virus_verdict=}')
    
    ## get user <> mail destination info 
    user_mailbox_request = requests.get(f'{api_url}/mailboxes', 
        params={
            'select' : '*,user:users(*)', # mailbox + user info
            'generated_email' : f'eq.{ses_mail_destination}'
        }, 
        headers={'Accept':'application/vnd.pgrst.object+json'}
    )

    if user_mailbox_request.ok:
        user_mailbox: dict = user_mailbox_request.json()

        ## mailbox validation
        if user_mailbox['is_blocked']:
            print('This mailbox is blocked... stopping relay!')
            return

    else:
        print('Failure to process email relay')
        print(f'request url: {unquote(user_mailbox_request.url)}')
        print(f'Response: {user_mailbox_request.text}')
        return


    s3_email_request = s3.get_object(Bucket=s3_bucket, Key=f'emails/{ses_mail_s3_id}')
    s3_email: bytes = s3_email_request['Body'].read()

    email_is_sent = False
    telegram_is_sent = False
    relay_fail_reason = None
    email_relayed_at = None
    # text separator for email
    text_separator = "-"*50

    if user_mailbox['relay_to_mail'] is True:
        relay_raw_email_header: bytes = f"To: {user_mailbox['user']['email']}\nSubject: Mail from ({ses_mail_source}) - {ses_mail_header_subject}\n".encode()
      
        # remove all headers and leave only the raw body of the mail
        relay_raw_email_body: bytes = s3_email[s3_email.find(b'Content-Type: '):]

        relay_raw_final_email: bytes = relay_raw_email_header + relay_raw_email_body
        print(f'{relay_raw_final_email=}')

        send_email_request = ses.send_raw_email(Source=emails_source, RawMessage={'Data': relay_raw_final_email})
        email_relayed_at = datetime.now()
        print(f'{send_email_request=}')

        email_is_sent: bool = send_email_request['ResponseMetadata']['HTTPStatusCode'] == 200
        relay_fail_reason = "SES_FAILURE" if email_is_sent is False else None

    if user_mailbox['relay_to_telegram'] is True:
        parsed_mail: mailparser.MailParser = mailparser.parse_from_bytes(s3_email)

        text_to_send = f'{text_separator}\n{text_separator}\nFrom: {ses_mail_source}\nSubject: {ses_mail_header_subject}\n{text_separator}\n\n{"".join(parsed_mail.text_plain)}'
        print(f'{text_to_send=}')

        telegram_request = telegram_send_msg(text_to_send, 21164173)
        print(f'{telegram_request=}')
        telegram_is_sent = telegram_request['ok'] is True
    
    
    
    create_mail_entry_request_data = {
        "mailbox_id" : user_mailbox['id'],
        "s3_file_id": ses_mail_s3_id,
        "received_at": ses_mail_header_date,
        "relayed_at": str(email_relayed_at) if email_relayed_at else None,
        "relay_fail_reason": relay_fail_reason if relay_fail_reason else None,
        "relayed_to_email": email_is_sent,
        "relayed_to_telegram": telegram_is_sent,
        "is_relayed": any([email_is_sent, telegram_is_sent]),
        "virus_verdict": ses_mail_virus_verdict,
        "spam_verdict": ses_mail_spam_verdict,
        "dkim_verdict": ses_mail_dkim_verdict,
        "spf_verdict": ses_mail_spf_verdict,
        "sender_mail_source": ses_mail_source,
    }
    print(f'{create_mail_entry_request_data=}')
    create_mail_entry_request = requests.post(f'{api_url}/mails', 
        headers={"Prefer": "return=representation", "Accept": "application/vnd.pgrst.object+json"}, 
        data=create_mail_entry_request_data
    )

    if email_is_sent is False:
        print('Relay of email has failed!')
        return

    return {"status": "relay_sucessful"}

