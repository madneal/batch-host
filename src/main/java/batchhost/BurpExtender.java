package batchhost;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.ui.UserInterface;


import java.util.ArrayList;
import java.util.List;

/**
 * Main class for the Batch Host Modifier Burp Suite extension using Montoya API.
 */
public class BatchHostModifierExtension implements BurpExtension {

    private ExtensionHelpers helpers;
    private UIController uiController;

    @Override
    public void initialize(ExtensionInitializationHandler initializationHandler) {
        this.helpers = initializationHandler.getHelpers();
        this.uiController = initializationHandler.getUIController();

        // Add a new suite tab
        initializationHandler.registerSuiteTab("Batch Host Modifier", this::createUI);
        initializationHandler.registerShortcut("Ctrl+Shift+H", this::showHelp);
    }

    /**
     * Creates the UI panel for the Batch Host Modifier tab.
     *
     * @return The main component of the tab.
     */
    private Component createUI() {
        return new BatchHostModifierPanel(helpers);
    }

    /**
     * Displays help information.
     */
    private void showHelp() {
        uiController.showMessage("Batch Host Modifier Extension\n\n" +
                "Enter hostnames and modify Host headers in selected requests.");
    }

    @Override
    public void terminate() {
        // Cleanup if necessary
    }
}

/**
 * UI Panel for the Batch Host Modifier.
 */
class BatchHostModifierPanel extends JPanel {

    private final ExtensionHelpers helpers;
    private final JTextArea hostInputArea;
    private final JButton batchSendButton;
    private final UIController uiController;

    public BatchHostModifierPanel(ExtensionHelpers helpers) {
        this.helpers = helpers;
        this.uiController = Burp.createUIController();

        setLayout(new BorderLayout());

        // Input Panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.setBorder(BorderFactory.createTitledBorder("Enter New Hostnames (one per line)"));

        hostInputArea = new JTextArea(10, 30);
        JScrollPane scrollPane = new JScrollPane(hostInputArea);
        inputPanel.add(scrollPane, BorderLayout.CENTER);

        // Button Panel
        batchSendButton = new JButton("Modify Host and Send in Batch");
        batchSendButton.addActionListener(e -> batchModifyAndSend());

        add(inputPanel, BorderLayout.CENTER);
        add(batchSendButton, BorderLayout.SOUTH);
    }

    /**
     * Modifies the Host header in selected requests and sends them in batch.
     */
    private void batchModifyAndSend() {
        String[] hosts = hostInputArea.getText().split("\\r?\\n");
        List<HttpRequestResponse> selectedRequests = uiController.getSelectedMessages();

        if (selectedRequests.isEmpty()) {
            uiController.showErrorMessage("No requests selected.");
            return;
        }

        List<HttpRequestResponse> sentRequests = new ArrayList<>();

        for (String host : hosts) {
            for (HttpRequestResponse reqResp : selectedRequests) {
                IHttpRequestInfo requestInfo = helpers.analyzeRequest(reqResp.getRequest());

                List<String> headers = new ArrayList<>(requestInfo.getHeaders());

                // Modify Host header
                boolean hostFound = false;
                for (int i = 0; i < headers.size(); i++) {
                    if (headers.get(i).startsWith("Host:")) {
                        headers.set(i, "Host: " + host.trim());
                        hostFound = true;
                        break;
                    }
                }
                if (!hostFound) {
                    headers.add("Host: " + host.trim());
                }

                byte[] body = requestInfo.getBody();
                byte[] newRequest = helpers.buildHttpMessage(headers, body);

                IHttpService httpService = reqResp.getHttpService();
                HttpRequestResponse newReqResp = Burp.sendToRepeater(httpService, newRequest);
                sentRequests.add(newReqResp);
            }
        }

        uiController.showMessage("Batch requests sent successfully.");
    }
}