package batchhost;

import burp.api.montoya.core.IHttpRequestResponse;
import burp.api.montoya.core.ExtensionHelpers;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * UI Panel for the Batch Host Modifier.
 */
public class BatchHostModifierPanel extends JPanel {

    private final ExtensionHelpers helpers;
    private final JTextArea hostInputArea;
    private final JButton batchSendButton;
    private final UserInterface userInterface;

    public BatchHostModifierPanel(ExtensionHelpers helpers, UserInterface userInterface) {
        this.helpers = helpers;
        this.userInterface = userInterface;

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
        List<IHttpRequestResponse> selectedRequests = userInterface.selectedMessages();

        if (selectedRequests.isEmpty()) {
            userInterface.showErrorMessage("No requests selected.");
            return;
        }

        for (String host : hosts) {
            for (IHttpRequestResponse reqResp : selectedRequests) {
                BurpExtenderUtils.modifyHostHeaderAndSend(helpers, userInterface, reqResp, host.trim());
            }
        }

        userInterface.showMessage("Batch requests sent successfully.");
    }
}