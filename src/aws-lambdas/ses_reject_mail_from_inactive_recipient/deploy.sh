echo "Zipping everything..."
zip -r function.zip .

echo "Uploading function.zip to lambda function"
aws lambda update-function-code --function-name ses_reject_mail_from_inactive_recipient --zip-file fileb://function.zip