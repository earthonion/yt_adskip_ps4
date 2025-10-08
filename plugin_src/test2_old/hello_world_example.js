/**
 * Hello World Example using the Welcome Dialog
 *
 * This demonstrates how to use the showWelcomeDialog function
 */

// Include the welcome_dialog.js functions
// (In practice, you would load this via <script src="welcome_dialog.js"></script>)

/**
 * Execute command on YouTube TV instance
 */
function executeYouTubeTVCommand(command, data) {
    for (var key in window._yttv) {
        if (window._yttv[key] &&
            window._yttv[key].instance &&
            window._yttv[key].instance.resolveCommand) {
            return window._yttv[key].instance.resolveCommand(command, data);
        }
    }
}

/**
 * Show welcome dialog with title and subtitle
 */
function showWelcomeDialog(title, subtitle, thumbnails) {
    var popupAction = {
        openPopupAction: {
            popupType: "TOAST",
            popup: {
                overlayToastRenderer: {
                    title: {
                        simpleText: title
                    },
                    subtitle: {
                        simpleText: subtitle
                    }
                }
            }
        }
    };

    if (thumbnails) {
        popupAction.openPopupAction.popup.overlayToastRenderer.image = {
            thumbnails: thumbnails
        };
    }

    executeYouTubeTVCommand(popupAction);
}

// ============================================
// HELLO WORLD EXAMPLES
// ============================================

// Example 1: Simple "Hello World"
showWelcomeDialog("Hello World", "This is a simple toast notification!");

// Example 2: With a delay (like in the original tizen.js)
setTimeout(() => {
    showWelcomeDialog("Hello World", "This message appears after 2 seconds");
}, 2000);

// Example 3: Custom message
showWelcomeDialog(
    "Custom Title",
    "You can put any text you want here as the subtitle"
);

// Example 4: Multi-line subtitle
showWelcomeDialog(
    "Welcome!",
    "This is line one. This is line two. You can add instructions or information here."
);

// Example 5: Testing different content
showWelcomeDialog(
    "Test Notification",
    "Press OK to continue. Press BACK to cancel."
);
