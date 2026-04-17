/**
 * DeIDGuard – content.js
 * Content Script (dynamically injected via chrome.scripting)
 *
 * Purpose: Capture the user's current text selection from any webpage.
 *
 * This script is injected into the active tab ONLY when:
 *  - The user clicks the toolbar icon, OR
 *  - The user triggers the keyboard shortcut (Ctrl+Shift+D / Cmd+Shift+D)
 *
 * Privacy:
 *  - This script does NOT transmit any data externally.
 *  - Selected text is returned only to the extension popup via chrome.runtime messaging.
 *  - No persistent listeners are left behind after the popup closes.
 */

'use strict';

/**
 * Returns the current text selection from the page.
 * Called via chrome.scripting.executeScript({ func: getSelectedText })
 *
 * @returns {string} The selected text, or empty string if nothing is selected.
 */
function getSelectedText() {
  const selection = window.getSelection();
  if (!selection || selection.rangeCount === 0) return '';

  const text = selection.toString();
  // Trim excess whitespace but preserve internal line breaks
  return text.trim();
}

// When injected as a function via executeScript, just return the result.
// This file also supports being injected as a full script file.
// In that case, we listen for a message from the popup.

if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'DEIDGUARD_GET_SELECTION') {
      const selected = getSelectedText();
      sendResponse({ text: selected, success: true });
    }
    // Return true to keep channel open for async response
    return true;
  });
}
