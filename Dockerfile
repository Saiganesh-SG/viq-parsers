FROM amazoncorretto:11-alpine-jdk
RUN apk update && apk upgrade
ENV ENVIRONMENT dev
ENV LATEST_FLAG false
ENV TOPIC_NAME cwe

# bash shell
RUN apk update && apk upgrade && apk add bash

# Create folders for interim storage
RUN bash -c 'mkdir -p /app/csw-{dev,qa,uat,prod}-dp/{sourcekeep,livekeep}/{cwe,cve}/{nvd,mitre} && mkdir -p /app/certs'

# Copy the cert
RUN cp /usr/lib/jvm/default-jvm/jre/lib/security/cacerts /app/certs/kafka.client.truststore.jks

COPY mitre-source-parser/target/mitre-source-parser*.jar /app/mitre-parser.jar
COPY nvd-source-parser/target/nvd-source-parser*.jar /app/nvd-parser.jar

WORKDIR /app

# java -jar -Dtopic=cve -Dlatest=true nvd-parser.jar
ENTRYPOINT ["java","-jar","-Dtopic=${TOPIC_NAME}","-Dlatest=${LATEST_FLAG}"]
