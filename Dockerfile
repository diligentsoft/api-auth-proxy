FROM openjdk:14.0.2

ARG JAR_FILENAME

EXPOSE 8080

WORKDIR /app
COPY target/${JAR_FILENAME} /app/app.jar

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

# -XX:+UseCGroupMemoryLimitForHeap
ENTRYPOINT /wait && exec java $JVM_OPTIONS -XX:+UnlockExperimentalVMOptions -XX:MaxRAMFraction=2 -Djava.awt.headless=true -jar  app.jar