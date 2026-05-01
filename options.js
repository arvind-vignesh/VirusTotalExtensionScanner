// 1. Listen for the Save button click
document.getElementById("save").addEventListener("click", () => {
  
  // 2. Grab the text from the input box
  let apiKey = document.getElementById("apiKey").value;

  // 3. Save it to Firefox's memory under the name "vtApiKey"
  browser.storage.local.set({ vtApiKey: apiKey }).then(() => {
    
    // 4. Show the "Saved!" text briefly
    let statusText = document.getElementById("status");
    statusText.style.display = "inline";
    
    setTimeout(() => {
      statusText.style.display = "none";
    }, 2000);
    
  });
});

// 5. When the options page opens, check if a key is already saved. If yes, put it in the box.
browser.storage.local.get("vtApiKey").then((result) => {
  if (result.vtApiKey) {
    document.getElementById("apiKey").value = result.vtApiKey;
  }
});