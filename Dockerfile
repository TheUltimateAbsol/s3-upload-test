# Stage 1: Build the application
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /app

# Copy dependency definitions first to cache dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source code and build
COPY src ./src
RUN mvn package -DskipTests

# Stage 2: Create the runtime image
FROM eclipse-temurin:17-jre-jammy

WORKDIR /app

# Copy the built jar from the builder stage
COPY --from=builder /app/target/s3pusher-1.0-SNAPSHOT-jar-with-dependencies.jar /app/s3pusher.jar

# Set the entrypoint
ENTRYPOINT ["java", "-jar", "/app/s3pusher.jar"]
