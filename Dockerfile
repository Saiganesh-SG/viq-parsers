FROM amazoncorretto:11-alpine-jdk
RUN apk update
RUN apk upgrade
RUN mkdir -p certs/
RUN cp /usr/lib/jvm/default-jvm/jre/lib/security/cacerts certs/kafka.client.truststore.jks
ARG JAR_FILE=mitre-source-parser/target/*.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
