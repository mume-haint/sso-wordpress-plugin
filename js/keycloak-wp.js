function saveTokens(kc) {
    window.sessionStorage.setItem('token', kc.token);
    window.sessionStorage.setItem('refreshToken', kc.refreshToken);
    window.sessionStorage.setItem('idToken', kc.idToken);
    
    window.sessionStorage.setItem('tokenParsed', JSON.stringify(kc.tokenParsed));
    window.sessionStorage.setItem('refreshTokenParsed', JSON.stringify(kc.refreshTokenParsed));
    window.sessionStorage.setItem('idTokenParsed', JSON.stringify(kc.idTokenParsed));
}

function restoreTokens(kc) {
    
    kc.token = window.sessionStorage.getItem('token');
    kc.refreshToken = window.sessionStorage.getItem('refreshToken');
    kc.idToken = window.sessionStorage.getItem('idToken');
    
    kc.tokenParsed = JSON.parse(window.sessionStorage.getItem('tokenParsed'));
    kc.refreshTokenParsed = JSON.parse(window.sessionStorage.getItem('refreshTokenParsed'));
    kc.idTokenParsed = JSON.parse(window.sessionStorage.getItem('idTokenParsed'));
    
    kc.timeSkew = 0;
}

function login(scope) {
    var loginOptions = {  
        scope: scope
    };

    keycloak.login(loginOptions);
}

// function loadProfile() {
//     keycloak.loadUserProfile().then(function(profile) {
//         output(profile);
//     }).catch(function() {
//         output('Failed to load profile');
//     });
// }

// function updateProfile() {
//     var url = keycloak.createAccountUrl().split('?')[0];
//     var req = new XMLHttpRequest();
//     req.open('POST', url, true);
//     req.setRequestHeader('Accept', 'application/json');
//     req.setRequestHeader('Content-Type', 'application/json');
//     req.setRequestHeader('Authorization', 'bearer ' + keycloak.token);

//     req.onreadystatechange = function () {
//         if (req.readyState == 4) {
//             if (req.status == 200) {
//                 output('Success');
//             } else {
//                 output('Failed');
//             }
//         }
//     }

//     req.send('{"email":"myemail@foo.bar","firstName":"test","lastName":"bar"}');
// }

// function loadUserInfo() {
//     keycloak.loadUserInfo().then(function(userInfo) {
//         output(userInfo);
//     }).catch(function() {
//         output('Failed to load user info');
//     });
// }

// function introspect() {
//     var url = keycloak.endpoints.token() + "/introspect";
//     var req = new XMLHttpRequest();
//     req.open('POST', url, true);
//     req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
//     req.onreadystatechange = function () {
//         if (req.readyState == 4) {
//             output("Check network to see introspection response");
//         }
//     }

//     req.send("token=" + keycloak.token + "&client_id=tpm-api&client_secret=e06cd4a2-881d-4015-905d-ae3102403191");
// }


// function refreshToken(minValidity) {
//     keycloak.updateToken(minValidity).then(function(refreshed) {
//         if (refreshed) {
//             output(keycloak.tokenParsed);
//         } else {
//             output('Token not refreshed, valid for ' + Math.round(keycloak.tokenParsed.exp + keycloak.timeSkew - new Date().getTime() / 1000) + ' seconds');
//         }
//     }).catch(function() {
//         output('Failed to refresh token');
//     });
// }

// function showExpires() {
//     if (!keycloak.tokenParsed) {
//         output("Not authenticated");
//         return;
//     }

//     var o = 'Token Expires:\t\t' + new Date((keycloak.tokenParsed.exp + keycloak.timeSkew) * 1000).toLocaleString() + '\n';
//     o += 'Token Expires in:\t' + Math.round(keycloak.tokenParsed.exp + keycloak.timeSkew - new Date().getTime() / 1000) + ' seconds\n';

//     if (keycloak.refreshTokenParsed) {
//         o += 'Refresh Token Expires:\t' + new Date((keycloak.refreshTokenParsed.exp + keycloak.timeSkew) * 1000).toLocaleString() + '\n';
//         o += 'Refresh Expires in:\t' + Math.round(keycloak.refreshTokenParsed.exp + keycloak.timeSkew - new Date().getTime() / 1000) + ' seconds';
//     }

//     output(o);
// }

function output(data) {
    if (typeof data === 'object') {
        data = JSON.stringify(data, null, '  ');
    }
    document.getElementById('output').innerHTML = data;
}

function event(event) {
    var e = document.getElementById('events').innerHTML;
    document.getElementById('events').innerHTML = new Date().toLocaleString() + "\t" + event + "\n" + e;
}
import Keycloak from 'https://cdn.jsdelivr.net/npm/keycloak-js@26.0.0/+esm';

const keycloak = new Keycloak({
    url: "http://auth.sso.beetdev.com",
    realm: "wp-mail-site-realm",
    clientId: "wp-site-1",
});
// try {
//     const silent_check_sso = window.location.origin + '/wp-content/plugins/sso-wp-master/js/silent-check-sso.html';
    
//     const authenticated = await keycloak.init({
//         onLoad: 'check-sso',
//         silentCheckSsoRedirectUri: silent_check_sso,
//         pkceMethod: 'S256'
//     });
//     console.log(authenticated)
//     if (authenticated) {
//         console.log('User is authenticated');
//     } else {
//         console.log('User is not authenticated');
//     }
// } catch (error) {
//     console.error('Failed to initialize adapter:', error);
// }
// var keycloak = Keycloak();

keycloak.onAuthSuccess = function () {
    event('Auth Success');
    saveTokens(keycloak);
};

keycloak.onAuthError = function (errorData) {
    event("Auth Error: " + JSON.stringify(errorData) );
};

keycloak.onAuthRefreshSuccess = function () {
    event('Auth Refresh Success');
};

keycloak.onAuthRefreshError = function () {
    event('Auth Refresh Error');
};

keycloak.onAuthLogout = function () {
    event('Auth Logout');
};

keycloak.onTokenExpired = function () {
    event('Access token expired.');
};

// Flow can be changed to 'implicit' or 'hybrid', but then client must enable implicit flow in admin console too 
const silent_check_sso = window.location.origin + '/wp-content/plugins/sso-wp-master/js/silent-check-sso.html';
var initOptions = {
    // responseMode: 'fragment',
    // flow: 'standard',
    // promiseType: 'native', 
    pkceMethod: 'S256',
    // 'check-sso' only authenticate the client if the user is already logged-in
    // if the user is not logged-in the browser will be redirected back to the application and remain unauthenticated.
    onLoad: 'check-sso', 
    // 'login-required' authenticate the client if the user is logged-in or display the login page if not
    // onLoad: 'login-required', 
    silentCheckSsoRedirectUri: silent_check_sso,
    // enable/disable monitoring login state; creates an hidden iframe that is used to detect if a Single-Sign Out has occurred
    checkLoginIframe: true
};

keycloak.init(initOptions).then(function(authenticated) {
    console.log('Init Success : '+authenticated);
    output('Init Success (' + (authenticated ? 'Authenticated' : 'Not Authenticated') + ')');		
    restoreTokens(keycloak);
}).catch(function(e) {
    console.log('Init Error', e);
    output('Init Error');
});