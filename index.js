const axios = require('axios');
const keycloakUrl = 'https://the1-corporate-iam.cloud-iam.com/auth/realms/integration-np/protocol/openid-connect/userinfo'

function generatePolicy(principalId, effect, resource, accessToken, errorMessage) {
    let authResponse = {
        "principalId": principalId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        }
    }
    authResponse.context = {
        "token": accessToken,
        "errorMessage": errorMessage || null
    };
    console.log("generate policy ", effect, " : ", authResponse.principalId);
    return authResponse;
}

function extractTokenFromHeader(event, callback) {
    let token = event.authorizationToken;
    let match = token.match(/^Bearer (.*)$/);
    if (!token || !match || match.length < 2) {
        console.log('extractTokenFromHeader error: ' + token);
        callback("Unauthorized")
    }
    return match[1];
}

async function verifyKeyCloakUser(accessToken, callback) {
    let reqHeader = {
        headers: {
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "authorization": `Bearer ${accessToken}`
        }
    }
    try {
        let resp = await axios.get(keycloakUrl, reqHeader)
        return resp
    }
    catch (err) {
        console.error('verifyUserkeycloak error:' + err);
        callback("Unauthorized");
    }
}

exports.handler = function (event, context, callback) {
    let token = extractTokenFromHeader(event, callback);
    verifyKeyCloakUser(token, callback).then(result => {
        if (result.isExpired == true) {
            callback(null, generatePolicy('user', 'Deny', event.methodArn, event.authorizationToken, errorMsgDenyPolicy(error)));
        } else {
            callback(null, generatePolicy('user', 'Allow', 'event.methodArn', event.authorizationToken));
        }
    })
}