require.config({
	baseUrl: "/admin/",
    urlArgs: "version=1.0.0",
	paths: {
		jquery: '/webjars/jquery/3.3.1/jquery.min',
		underscore: '/webjars/underscorejs/1.8.3/underscore-min',
		handlebars: '/webjars/handlebars/4.0.5/handlebars.min',
		bootstrap: '/webjars/bootstrap/3.3.7-1/js/bootstrap.min',
		backbone: '/webjars/backbonejs/1.3.3/backbone-min',
		text: '/webjars/requirejs-text/2.0.15/text',
		'auth0-js': "/webjars/auth0.js/9.2.3/build/auth0",
        Noty: '/webjars/noty/3.1.4/lib/noty',
        userManagement: "userManagement/",
        common: "common/",
        tos: "tos/"
    },
    shim: {
        "bootstrap": {
            deps: ["jquery"]
        },
        "auth0-js": {
            deps:["jquery"],
            exports: "Auth0Lock"
        }
    }
});

require(["backbone", "common/session", "common/router", "underscore", "jquery", "bootstrap"],
    function(Backbone, session, router, _){
        Backbone.history.start({pushState:true});
        document.onmousemove = session.activity;
        document.onkeyup = session.activity;
    });
