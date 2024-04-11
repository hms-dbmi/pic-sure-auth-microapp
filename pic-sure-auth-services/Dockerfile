FROM amazoncorretto:21.0.1-alpine3.18

# Copy jar and access token from maven build
COPY target/pic-sure-auth-services-*.jar /pic-sure-auth-service.jar

ENTRYPOINT ["sh", "-c", "java ${JAVA_OPTS} -jar /pic-sure-auth-service.jar"]