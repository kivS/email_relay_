const AWS = require('aws-sdk');
const axios = require('axios');

// TODO: api url here needs to change afterwards
const api_url = process.env.API_URL

exports.handler = function(event, context, callback) {
  
    if(!api_url) throw Error('EMAIL_RELAY_API_URL missing!!');
    console.debug(`EMAIL_RELAY_API_URL: ${api_url}`)
  
    var sesNotification = event.Records[0].ses;
    // console.log("SES Notification:\n", JSON.stringify(sesNotification, null, 2));
    
    let sender = sesNotification.mail.source
    console.debug('Email sender: ', sender)
    
    let destination = sesNotification.mail.destination[0]
    console.debug('Email destination: ', destination)

    axios.get(`${api_url}/internal_api/check_if_email_is_allowed`, {
      params:{
        "destination_email" : destination
      },
      headers:{
        
    } 
    }).then(response =>{
        console.debug('response data: ', response.data)
        
        if (response.data.is_blocked){
            console.error(`${destination} is not valid... let's bounce back`)
            // continue with bounce processing
            callback(null, {'disposition':'CONTINUE'});
        }else{
            console.info(`${destination} is valid... continue mail flow`)
            // continue with the ruleset to process the emails
            callback(null, {'disposition':'STOP_RULE'});    
        }
    }).catch(error =>{
        // TODO: we need to send these errors to telegram as well yo!
        console.error('Something went wrong...', error.response.data)
        console.debug(error.request._header)
        // continue with the ruleset to process the recovery of the emails
        callback(null, {'disposition':'STOP_RULE'}); 
    })
};