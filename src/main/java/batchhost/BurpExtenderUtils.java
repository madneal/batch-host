package batchhost;

import burp.api.montoya.core.IHttpRequestResponse;
import burp.api.montoya.core.IExtensionHelpers;
import burp.api.montoya.core.IHttpService;
import burp.api.montoya.core.IRequestInfo;
import burp.api.montoya.ui.UserInterface;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility class containing helper methods for the extension.
 */
public class BurpExtenderUtils {

    /**
     * Modifies the Host header in the request and sends it using Burp Suite's Repeater.
     *
     * @param helpers        Extension helpers for manipulating requests.
     * @param userInterface  User interface for interacting with Burp Suite.
     * @param reqResp        The original HTTP request/response to modify and send.
     * @param newHost        The new Host header value.
     */
    public static void modifyHostHeaderAndSend(IExtensionHelpers helpers, UserInterface userInterface,
                                               IHttpRequestResponse reqResp, String newHost) {
        // Analyze the original request
        IRequestInfo requestInfo = helpers.analyzeRequest(reqResp.request());

        // Get original headers and body
        List<String> headers = new ArrayList<>(requestInfo.headers());
        byte[] body = helpers.body(reqResp.request());

        // Modify or add the Host header
        boolean hostFound = false;
        for (int i = 0; i < headers.size(); i++) {
            if (headers.get(i).startsWith("Host:")) {
                headers.set(i, "Host: " + newHost);
                hostFound = true;
                break;
            }
        }
        if (!hostFound) {
            headers.add("Host: " + newHost);
        }

        // Rebuild the HTTP message with modified headers
        byte[] newRequest = helpers.buildHttpMessage(headers, body);

        // Get the original HTTP service
        IHttpService httpService = reqResp.httpService();

        // Send the modified request to Repeater
        userInterface.sendToRepeater(httpService, newRequest);
    }
}
