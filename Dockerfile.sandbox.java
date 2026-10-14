# Sandbox image for JAVA repos (Maven). Contains NO credentials. The agent runs it with:
#   --network none --read-only --cap-drop ALL --user 65534  and a per-run COPY of the dependency cache mounted as HOME.
# Build:  docker build -f Dockerfile.sandbox.java -t maintenance-agent-sandbox:java .
# Use:    python -m agent run <repo> --sandbox docker --docker-image maintenance-agent-sandbox:java \
#                --java-cache /path/to/warm/.m2   [--prefetch-network]
# Warm the cache ONCE in trusted CI:  mvn -B dependency:go-offline test-compile  (and one `mvn -B verify`,
# so surefire's JUnit provider jars are cached too), then point --java-cache at that ~/.m2 directory.
FROM maven:3.9-eclipse-temurin-17
RUN mkdir -p /home/sandbox && chown 65534:65534 /home/sandbox
WORKDIR /work
