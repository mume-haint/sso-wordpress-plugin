function saveTokens(kc) {
    window.sessionStorage.setItem('token', kc.token);
    window.sessionStorage.setItem('refreshToken', kc.refreshToken);
    window.sessionStorage.setItem('idToken', kc.idToken);

    window.sessionStorage.setItem('tokenParsed', JSON.stringify(kc.tokenParsed));
    window.sessionStorage.setItem('refreshTokenParsed', JSON.stringify(kc.refreshTokenParsed));
    window.sessionStorage.setItem('idTokenParsed', JSON.stringify(kc.idTokenParsed));
}

function restoreTokens(kc) {
    if ( !document.body.classList.contains( 'logged-in' ) ) {
        kc.token = window.sessionStorage.getItem('token');
        kc.refreshToken = window.sessionStorage.getItem('refreshToken');
        kc.idToken = window.sessionStorage.getItem('idToken');

        kc.tokenParsed = JSON.parse(window.sessionStorage.getItem('tokenParsed'));
        kc.refreshTokenParsed = JSON.parse(window.sessionStorage.getItem('refreshTokenParsed'));
        kc.idTokenParsed = JSON.parse(window.sessionStorage.getItem('idTokenParsed'));

        kc.timeSkew = 0;
        var token = kc.token;
        let idToken = kc.idToken;
        //call ajax vao function set_wordpress_user\
        window.location.href = window.location.origin + `/handle-token-endpoint?token=${token}&id_token=${idToken}`
    }

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
//     document.getElementById('output').innerHTML = data;
}

function event(event) {
//     var e = document.getElementById('events').innerHTML;
//     document.getElementById('events').innerHTML = new Date().toLocaleString() + "\t" + event + "\n" + e;
}
import Keycloak from 'https://cdn.jsdelivr.net/npm/keycloak-js@26.0.0/+esm';

const keycloak = new Keycloak({
    url: ssoData.keycloak_url,
    realm: ssoData.keycloak_realm,
    clientId: ssoData.keycloak_client_id,

});

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
const silent_check_sso = window.location.origin + '/wp-content/plugins/sso-wordpress-plugin/js/silent-check-sso.html';
var initOptions = {
    onLoad: 'check-sso',
    silentCheckSsoRedirectUri: silent_check_sso,
    checkLoginIframe: true,
    flow: 'standard',
};

keycloak.init(initOptions).then(function(authenticated) {
    console.log('Init Success : '+authenticated);
    output('Init Success (' + (authenticated ? 'Authenticated' : 'Not Authenticated') + ')');
    if(authenticated){
        restoreTokens(keycloak);
    }else{
        if ( document.body.classList.contains( 'logged-in' ) ) {
            var host = window.location.origin;
            window.location.replace(host+"/handle-logout-keycloak");
            console.log('User is not authenticated');
        }
    }

// 	window.location.replace(window.location.origin+"/handle-auth-code");
}).catch(function(e) {
    console.log('Init Error', e);
    output('Init Error');
});