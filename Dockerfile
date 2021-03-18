FROM amazoncorretto:11-alpine-jdk
RUN apk update
RUN apk upgrade
ARG JAR_FILE=mitre-source-parser/target/*.jar
COPY ${JAR_FILE} app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
