FROM tomcat:9-jdk11
RUN cp -r /usr/local/tomcat/webapps.dist/* /usr/local/tomcat/webapps/ \
 && sed -i 's|<Valve className="org.apache.catalina.valves.RemoteAddrValve".*/>||' \
        /usr/local/tomcat/webapps/manager/META-INF/context.xml \
 && sed -i 's|<Valve className="org.apache.catalina.valves.RemoteAddrValve".*/>||' \
        /usr/local/tomcat/webapps/host-manager/META-INF/context.xml
COPY tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
EXPOSE 8080
