const keycloakClient = require('keycloak-backend').Keycloak;
const keycloak = new keycloakClient({
    "realm": "integration-np",
    "keycloak_base_url": "https://the1-corporate-iam.cloud-iam.com/auth"
})

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
    try {
        const resp = await keycloak.jwt.verify(accessToken);
        return resp
    }
    catch (err) {
        console.error('verify KeyCloakUser error: ', err);
        callback("Unauthorized");
    }
}

exports.handler = function (event, context, callback) {
   // let token = extractTokenFromHeader(event, callback);
    let token = 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJOQzB0TERTdGJpc1VuYV9tTG9ZNzljU0wxVXYtXzBDRkxXSkQtMzh5aXVjIn0.eyJleHAiOjE2ODMxODU1MTEsImlhdCI6MTY4MzE4MzcxMSwianRpIjoiN2RmYzllMzAtMDJiNy00YTdiLWI2ZTktYjQ2ZTQzZDlhNGM2IiwiaXNzIjoiaHR0cHM6Ly90aGUxLWNvcnBvcmF0ZS1pYW0uY2xvdWQtaWFtLmNvbS9hdXRoL3JlYWxtcy9pbnRlZ3JhdGlvbi1ucCIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI2MDNlZjY4YS0yYTNlLTQ2NWEtODk2MC1kOWQ4MzAzYzI5ZWMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJwYXJ0bmVyIiwic2Vzc2lvbl9zdGF0ZSI6ImNmMzI2M2I0LTU5NzctNDExNS05ZTRhLTc4ODNjMzIzMGJmNSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLWludGVncmF0aW9uLW5wIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGxveWFsdHkubWVtYmVyLmxpc3Q6cmVhZDpjcmVhdGU6dXBkYXRlOmRlbGV0ZSIsInNpZCI6ImNmMzI2M2I0LTU5NzctNDExNS05ZTRhLTc4ODNjMzIzMGJmNSJ9.RW_z5MW6mXOI28fwTxgew-bj3Ja64izX9BsDcqt5ywsMdbxKkn5zLqhoKRb4BJlCpNpj3-Rm0yvLfIzBn1TZwGdQmqSvcBO35sVe-uch70Vij9whVnHLwQXdcFuUbVfkpHS_8wsIzCNJVS0XsDBHbB_Hn_iQP2R8fyuuG3I9YhxiaowES6DZ7N1kix5zMMSgg-1KAirb1SQiBwPaVYm1ozTyvOYwLLRNPaghPUW1NylAcZ6uBsn0CQq-kXtsbMFx8GM4CbRP99xILUD4ePZx4rn5-lbsPNLQHJ6IqqxqkZNsJA9AAE817HaDJOQCX25hjpHgx7pIg7FthX6cIpWCgQ';
   
    verifyKeyCloakUser(token, callback).then(result => {
        if (result.isExpired == true) {
            callback(null, generatePolicy('user', 'Deny', event.methodArn, event.authorizationToken, errorMsgDenyPolicy(error)));
        } else {
            callback(null, generatePolicy('user', 'Allow', 'event.methodArn', event.authorizationToken));
        }
    })
}
module.exports.handler();