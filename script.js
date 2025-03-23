function scanWebsite() {
    const urlInput = document.getElementById("url-input").value;
    const scanStatus = document.getElementById("scan-status");
    const scanResult = document.getElementById("scan-result");

    if (!urlInput) {
        scanStatus.innerText = "Please enter a valid URL.";
        scanResult.innerText = "";
        return;
    }

    scanStatus.innerText = `The crawlers are crawling '${urlInput}'...`;
    scanResult.innerText = "";
    scanResult.className = "";
    scanStatus.classList.add("loading");

    setTimeout(() => {
        const riskScore = Math.floor(Math.random() * 100);
        let resultText = "";
        let resultClass = "";

        if (riskScore < 50) {
            resultText = "Safe website";
            resultClass = "safe";
        } else if (riskScore >= 50 && riskScore < 70) {
            resultText = "Suspicious website";
            resultClass = "suspicious";
        } else {
            resultText = "Phishing website detected!";
            resultClass = "phishing";
        }

        scanStatus.classList.remove("loading");
        scanResult.innerText = `${resultText} (Risk Score: ${riskScore})`;
        scanResult.className = resultClass + " fade-in";
    }, 2000);
}
