package batchhost;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.ExtensionHelpers;
import burp.api.montoya.ui.UserInterface;


import java.awt.*;

/**
 * Main class for the Batch Host Modifier Burp Suite extension using Montoya API.
 */
public class BatchHostModifierExtension implements BurpExtension {

    private ExtensionHelpers helpers;
    private UserInterface userInterface;

    @Override
    public void initialize(ExtensionHelpers helpers, UserInterface userInterface) {
        this.helpers = helpers;
        this.userInterface = userInterface;

        // Register a new suite tab
        userInterface.registerSuiteTab("Batch Host Modifier", this::createBatchHostModifierTab);
    }

    /**
     * Creates the UI panel for the Batch Host Modifier tab.
     *
     * @return The main component of the tab.
     */
    private Component createBatchHostModifierTab() {
        return new BatchHostModifierPanel(helpers, userInterface);
    }

    @Override
    public void extensionUnloaded() {
        // Perform any necessary cleanup here
    }
}