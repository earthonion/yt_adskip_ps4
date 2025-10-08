/**
 * Welcome Dialog Function - Remake
 *
 * Original function found in tizen.js:380
 * This function displays a toast notification dialog with title and subtitle
 *
 * @param {string} title - The main title text for the toast
 * @param {string} subtitle - The subtitle/description text
 * @param {Array} thumbnails - Optional array of thumbnail images
 */
function showWelcomeDialog(title, subtitle, thumbnails) {
    // Create the popup action object structure
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

    // Add thumbnails if provided
    if (thumbnails) {
        popupAction.openPopupAction.popup.overlayToastRenderer.image = {
            thumbnails: thumbnails
        };
    }

    // Execute the command using the YouTube TV instance
    executeYouTubeTVCommand(popupAction);
}

/**
 * Execute command on YouTube TV instance
 *
 * Original function E found in tizen.js:770
 * Searches for YouTube TV instance and executes the command
 *
 * @param {Object} command - The command object to execute
 * @param {*} data - Optional data parameter
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

// Example usage (as seen in tizen.js:2049):
// setTimeout(() => {
//     showWelcomeDialog(
//         "Welcome to TizenTube",
//         "Go to settings and scroll down to TizenTube category to open TizenTube Settings, open playback settings, click on Speed to open Video Speed Settings and press [RED] to open TizenTube Theme Settings."
//     );
// }, 2000);
