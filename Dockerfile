FROM amazoncorretto:11-alpine-jdk
RUN apk update
RUN apk upgrade
RUN mkdir -p /csw-dev-dp/sourcekeep/cwe/mitre/
RUN mkdir -p /csw-dev-dp/livekeep/cwe/mitre/
RUN mkdir -p /certs/
RUN cp /usr/lib/jvm/default-jvm/jre/lib/security/cacerts /certs/kafka.client.truststore.jks
ARG JAR_FILE=mitre-source-parser/target/*.jar
COPY ${JAR_FILE} mitre-parser.jar
ARG JAR_FILE=nvd-source-parser/target/*.jar
COPY ${JAR_FILE} nvd-parser.jar
ENTRYPOINT ["java","-jar","/mitre-parser.jar"]
