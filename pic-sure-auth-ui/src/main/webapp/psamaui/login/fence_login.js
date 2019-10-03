define(['common/session', 'picSure/settings', 'common/searchParser', 'jquery', 'handlebars', 'text!login/login.hbs', 'text!login/not_authorized.hbs', 'overrides/login', 'util/notification'],
    function(session, settings, parseQueryString, $, HBS, loginTemplate, notAuthorizedTemplate, overrides, notification){
        var loginTemplate = HBS.compile(loginTemplate);

        var login = {
            showLoginPage : function(){

                // Check if the `code` parameter is set in the URL, as it would be, when
                // FENCE redirects back after authentication.
                var queryString = window.location.search.substring(1);
                var params = {}, queries, temp, i, l;
                // Split into key/value pairs
                queries = queryString.split("&");
                // Convert the array of strings into an object
                for ( i = 0, l = queries.length; i < l; i++ ) {
                    temp = queries[i].split('=');
                    params[temp[0]] = temp[1];
                }
                var code = params['code'];
                if (code) {
                    $('#main-content').html('DataStage authentication is successful. Processing UserProfile information...');
                    $.ajax({
                        url: '/psama/authentication',
                        type: 'post',
                        data: JSON.stringify({
                           code: code
                        }),
                        contentType: 'application/json',
                        success: function(data){
                            console.log('showLoginPage() psama fence-authentication is successful.');
                            console.log(data);

                            // If back-end response is success, we will get a PSAMA JWT token back, and some
                            // other information. We will set the session variables for the user with our own
                            // internal expiry, and other claims.
                            session.authenticated(
                                data.userId,
                                data.token,
                                data.email,
                                data.permissions,
                                data.acceptedTOS,
                                this.handleNotAuthorizedResponse
                            );

                            if (data.acceptedTOS !== 'true'){
                                history.pushState({}, "", "/psamaui/tos");
                            } else {
                                window.location = '/picsureui';
                            }

                        }.bind(this),
                        error: function(data){
                            notification.showFailureMessage("Failed to authenticate with provider. Try again or contact administrator if error persists.")
                            history.pushState({}, "", sessionStorage.not_authorized_url? sessionStorage.not_authorized_url : "/psamaui/not_authorized?redirection_url=/picsureui");
                        }
                    });
                    return null;
                } else {
                    console.log("FENCE-showLoginPage() no code in query string, redirecting to FENCE");
                    // This is the initial login, when there is no code present
                    $('#main-content').html('Authentication will be performed via DataStage FENCE pseudo-protocol.');
                    window.location = settings.idp_provider_uri + "/user/oauth2/authorize"+
                        "?response_type=code"+
                        "&scope=user+openid"+
                        "&client_id=" + settings.fence_client_id +
                        "&redirect_uri="+settings.fence_redirect_url;
                    return null;
                }
                console.log("FENCE-showLoginPage() finished");
            },
            handleNotAuthorizedResponse : function () {
                console.log("FENCE-handleNotAuthorizedResponse() starting....");
                console.log("FENCE-handleNotAuthorizedResponse() sessionStorage");
                console.log(sessionStorage);

                if (JSON.parse(sessionStorage.session).token) {
                    if (sessionStorage.not_authorized_url)
                        window.location = sessionStorage.not_authorized_url;
                    else
                        window.location = "/psamaui/not_authorized" + window.location.search;
                }
                else {
                    console.log("fence_login!!!!!!!");console.log("fence_login!!!!!!!");console.log("fence_login!!!!!!!");
                    //window.location = "/psamaui/logout" + window.location.search;
                }
            },
            displayNotAuthorized : function () {
                console.log("FENCE-displayNotAuthorized() starting...");

                if (overrides.displayNotAuthorized)
                    overrides.displayNotAuthorized()
                else
                    $('#main-content').html(HBS.compile(notAuthorizedTemplate)({helpLink:settings.helpLink}));
            }
        };
        return login;
    });