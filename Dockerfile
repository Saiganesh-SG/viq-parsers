FROM amazoncorretto:11-alpine-jdk
RUN apk update && apk upgrade
ENV ENVIRONMENT dev
ENV LATEST_FLAG false
ENV TOPIC_NAME cwe

# Create folders for interim storage based on bucket-name
RUN mkdir -p /app/csw-${ENVIRONMENT}-dp/sourcekeep/cwe/mitre && mkdir -p /app/csw-${ENVIRONMENT}-dp/livekeep/cwe/mitre && mkdir -p /app/csw-${ENVIRONMENT}-dp/sourcekeep/cve/nvd && mkdir -p /app/csw-${ENVIRONMENT}-dp/livekeep/cve/nvd && mkdir -p /app/certs

# Code has reference to /csw-dev-dp .. so creating symlink for backward comptability until code is updated
RUN cd / && ln -s /app/csw-${ENVIRONMENT}-dp csw-${ENVIRONMENT}-dp && ln -s /app/certs certs

# Copy the cert
RUN cp /usr/lib/jvm/default-jvm/jre/lib/security/cacerts /app/certs/kafka.client.truststore.jks

COPY mitre-source-parser/target/mitre-source-parser*.jar /app/mitre-parser.jar
COPY nvd-source-parser/target/nvd-source-parser*.jar /app/nvd-parser.jar

WORKDIR /app

# java -jar -Dtopic=cve -Dlatest=true nvd-parser.jar
ENTRYPOINT ["java","-jar","-Dtopic=${TOPIC_NAME}","-Dlatest=${LATEST_FLAG}"]
