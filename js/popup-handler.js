jQuery(document).ready(function($) {
    // Function to get query parameter by name
    function getQueryParam(name) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(name);
    }

    const authCode = getQueryParam('code');

    if (window.opener) {
        console.log('This page was opened as a popup.');

        if (authCode) {
            window.opener.postMessage({
                status: 'logged_in',
                message: 'User successfully logged in!',
                code: authCode
            }, window.location.origin);
        } else {
            console.error('No authorization code found in the URL.');
        }

        window.close();
    }
});
