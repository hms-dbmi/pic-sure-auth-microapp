# pic-sure-auth-microapp

Instructions to launch in dev mode:

Prerequisites: Maven 3+, Java, Docker and docker-compose

mvn clean install && docker-compose build && docker-compose up -d

You'll need to provide Auth0 client_id in /admin/overrides/login.js and the client_secret of pic-sure-auth-services 
has to match the one from Auth0 based on client_id.

# login to pic-sure-auth-services endpoint
after you run the command `docker-compose up -d`, and check everything is fine by `docker-compose logs -f`

you can try to hit the endpoint: `http://{{your_docker_machine_ip_address}}:8080/pic-sure-auth-services/auth/user
with headers - Authorization:Bearer {{your_token}}`
The token could be generated by the repo `https://github.com/hms-dbmi/jwt-creator`
The default userId is `foo@bar.com`

#
If you make source code changes, just re-run the same command and it will redeploy the stack for you.

This was changed from the much shorter maven based deployment to resolve a certificate issue with grin-docker-dev. Once the cert issue is resolved the maven tomcat configs will work again.

Then open your browser at http://<your docker-machine ip>


