echo "Zipping everything..."
# dependencies at the root of the function.zip
cd external_dependencies; zip -r ../function.zip *; cd ..
# adding code to zip
zip -g function.zip lambda_function.py .python-version

echo "Uploading function.zip to lambda function"
aws lambda update-function-code --function-name process-email-relay --zip-file fileb://function.zip