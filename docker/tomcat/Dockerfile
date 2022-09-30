FROM hub-registry-quay-quay-enterprise.apps.hub01.test.ocp.example.com/ocpv4-stage/cissecure/jboss-webserver-5/jws56-openjdk11-openshift-rhel8:5.6.2-7

# Set proxies if needed
ENV http_proxy=http://p1proxy.example.com:8080
ENV https_proxy=http://p1proxy.example.com:8080
ENV no_proxy=localhost,127.0.0.1,.example.com,.example.pvt

# CIS Tomcat9 - 2.5
ENV JWS_SERVER_NAME=Webserver

# CIS Tomcat9 - 3.1
ENV TOMCAT_SHUTDOWN=ShutItDown

# Elevate
USER root

# Test stuff
RUN yum -y install python3 dos2unix nmap-ncat bind-utils diffutils less curl zip unzip && yum clean all && rm -fR /var/cache/yum 

ADD security /security
RUN chown -R 1001:1001 /security

# CIS Tomcat9 1.1
RUN rm -rf $JWS_HOME/webapps/ROOT && rm -f $JWS_HOME/webapps/ROOT.war

# CIS Tomcat9 - 4.1, 4.3, 4.4, 4.5, 4.6, 4.7
RUN chmod 770 $JWS_HOME && chmod 770 $JWS_HOME/conf && chmod 770 $JWS_HOME/logs && \
    chmod 770 $JWS_HOME/temp && chmod 770 $JWS_HOME/bin && chmod 770 $JWS_HOME/webapps

# CIS Tomcat9 - 4.8
RUN chmod 660 $JWS_HOME/conf/catalina.properties
# CIS Tomcat9 - 4.9
RUN chmod 660 $JWS_HOME/conf/catalina.policy
# CIS Tomcat9 - 4.10
RUN chmod 660 $JWS_HOME/conf/context.xml
# CIS Tomcat9 - 4.11
RUN chmod 640 $JWS_HOME/conf/logging.properties
# CIS Tomcat9 - 4.12
RUN chmod 660 $JWS_HOME/conf/server.xml
# CIS Tomcat9 - 4.13
RUN chmod 660 $JWS_HOME/conf/tomcat-users.xml
# CIS Tomcat9 - 4.14
RUN chmod 660 $JWS_HOME/conf/web.xml
# CIS Tomcat9 - 4.15
RUN chmod 660 $JWS_HOME/conf/jaspic-providers.xml

# CIS Tomcat9 - 10.6, 10.7, 10.8
ADD docker/tomcat/catalina.sh $JWS_HOME/bin/launch/catalina.sh
RUN chmod 664 $JWS_HOME/bin/launch/catalina.sh && chown 185:root $JWS_HOME/bin/launch/catalina.sh

# CIS Tomcat9 - 10.9, 10.10
ADD docker/tomcat/server.xml $JWS_HOME/conf/server.xml
RUN chmod 660 $JWS_HOME/conf/server.xml && chown jboss:root $JWS_HOME/conf/server.xml

ADD docker/tomcat/https.sh $JWS_HOME/bin/launch/https.sh
RUN chmod 664 $JWS_HOME/bin/launch/https.sh && chown 185:root $JWS_HOME/bin/launch/https.sh

# CIS Tomcat9 - 10.12
ADD docker/tomcat/context.xml $JWS_HOME/conf/context.xml
RUN chmod 660 $JWS_HOME/conf/context.xml && chown 185:root $JWS_HOME/conf/context.xml

# CIS Tomcat9 - 2.1, 2.2, 2.3
# Preventing Server Identification
RUN unzip $JWS_HOME/lib/catalina.jar -d /tmp
ADD docker/tomcat/conf/org/apache/catalina/util/ServerInfo.properties \
    /tmp/org/apache/catalina/util/ServerInfo.properties
RUN cd /tmp && zip -r catalina.jar org/ module-info.class META-INF/ && \
    cp -f /tmp/catalina.jar $JWS_HOME/lib/catalina.jar && chown 185:root $JWS_HOME/lib/catalina.jar && \
    chmod 644 $JWS_HOME/lib/catalina.jar && rm -f /tmp/catalina.jar && rm -rf /tmp/org && \
    rm -f /tmp/module-info.class && rm -rf /tmp/META-INF

# Run CIS Audit at Build Time
RUN cd /security && python run_benchmark.py -i ./benchmarks/cis_tomcat9.json \
    -a -s "5.1,6.1,6.5,7.6,9.1,9.3,10.2,10.11,10.19" | tee /security/cis_results.log && \
    chown 1001:1001 /security/cis_results.log && chmod 444 /security/cis_results.log

# JWS User
USER 185




