#!/bin/sh
SAVED="$(pwd)"
cd "$(dirname "$0")/" >/dev/null
APP_HOME="$(pwd -P)"
cd "$SAVED" >/dev/null
CLASSPATH="${APP_HOME}/gradle/wrapper/gradle-wrapper.jar"
JAVACMD="${JAVA_HOME:+$JAVA_HOME/bin/}java"
exec "$JAVACMD" -Xmx64m -Xms64m \
    "-Dorg.gradle.appname=$(basename "$0")" \
    -classpath "$CLASSPATH" \
    org.gradle.wrapper.GradleWrapperMain "$@"
