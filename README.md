KSCDashBoard
============

A DashBoard based on KSC report

diff installKscDash/WEB-INF/applicationContext-spring-security.xml /usr/share/opennms/jetty-webapps/opennms/WEB-INF/applicationContext-spring-security.xml
cp installKscDash/WEB-INF/applicationContext-spring-security.xml /usr/share/opennms/jetty-webapps/opennms/WEB-INF/applicationContext-spring-security.xml
cp installKscDash/ascoTlcDashboard.jsp /usr/share/opennms/jetty-webapps/opennms/
cp installKscDash/WEB-INF/lib/opennms-ksc-dashboard-2.19.1-SNAPSHOT.jar  /usr/share/opennms/jetty-webapps/opennms/WEB-INF/lib/
cp installKscDash/WEB-INF/jsp/dashboard/ascoTlcCustomView.jsp /usr/share/opennms/jetty-webapps/opennms/WEB-INF/jsp/dashboard/ascoTlcCustomView.jsp
diff installKscDash/WEB-INF/web.xml /usr/share/opennms/jetty-webapps/opennms/WEB-INF/web.xml
cp installKscDash/WEB-INF/web.xml /usr/share/opennms/jetty-webapps/opennms/WEB-INF/web.xml
cp installKscDash/WEB-INF/kscDispatcher-servlet.xml  /usr/share/opennms/jetty-webapps/opennms/WEB-INF
