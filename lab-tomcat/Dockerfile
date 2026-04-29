FROM tomcat:9-jdk11

# Expose the manager + host-manager apps to anyone on the network (drops
# RemoteAddrValve which normally restricts to localhost).
RUN cp -r /usr/local/tomcat/webapps.dist/* /usr/local/tomcat/webapps/ \
 && sed -i 's|<Valve className="org.apache.catalina.valves.RemoteAddrValve".*/>||' \
        /usr/local/tomcat/webapps/manager/META-INF/context.xml \
 && sed -i 's|<Valve className="org.apache.catalina.valves.RemoteAddrValve".*/>||' \
        /usr/local/tomcat/webapps/host-manager/META-INF/context.xml

# Enable the AJP connector on 0.0.0.0:8009 with secretRequired="false".
# This is CVE-2020-1938 (Ghostcat) territory — AJP file inclusion via the
# javax.servlet.include.* attributes from a crafted forwarded request.
RUN sed -i 's|</Service>|<Connector protocol="AJP/1.3" address="0.0.0.0" port="8009" redirectPort="8443" secretRequired="false" allowedRequestAttributesPattern=".*"/></Service>|' \
        /usr/local/tomcat/conf/server.xml

COPY tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml

# Drop a deliberately vulnerable webapp that calls ObjectInputStream.readObject
# on user-controlled data (Java deserialization sink). Without a gadget chain
# on the classpath this is a detection signal rather than a working RCE — the
# point is the audit recognises the unsafe pattern.
RUN mkdir -p /usr/local/tomcat/webapps/vuln
COPY vuln-index.jsp /usr/local/tomcat/webapps/vuln/index.jsp

EXPOSE 8009 8080
