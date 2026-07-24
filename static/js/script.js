document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const scanInput = document.getElementById('scanInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultBox = document.getElementById('resultBox');
    const scanBtnText = document.getElementById('scanBtnText');
    const scanSpinner = document.getElementById('scanSpinner');

    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = scanInput.value.trim();
            if (!url) return;

            // UI Loading state
            scanBtn.disabled = true;
            if (scanBtnText) scanBtnText.textContent = "Scanning...";
            if (scanSpinner) scanSpinner.style.display = "inline-block";
            if (resultBox) resultBox.style.display = "none";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();

                if (!response.ok) {
                    alert(data.error || 'Failed to scan URL');
                    return;
                }

                // Render result box
                if (resultBox) {
                    const badgeClass = data.prediction === 'Safe' ? 'badge-safe' : 'badge-phishing';
                    
                    document.getElementById('resPrediction').className = `badge ${badgeClass}`;
                    document.getElementById('resPrediction').textContent = data.prediction;
                    document.getElementById('resConfidence').textContent = `${data.confidence}%`;
                    document.getElementById('resDomain').textContent = data.domain || 'N/A';
                    document.getElementById('resIp').textContent = data.ip_address || 'N/A';
                    document.getElementById('resLength').textContent = data.url_length;
                    document.getElementById('resHttps').textContent = data.is_https ? 'Yes' : 'No';

                    resultBox.style.display = 'block';
                    resultBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }

            } catch (err) {
                console.error(err);
                alert("An error occurred while connecting to the scan server.");
            } finally {
                scanBtn.disabled = false;
                if (scanBtnText) scanBtnText.textContent = "Scan URL";
                if (scanSpinner) scanSpinner.style.display = "none";
            }
        });
    }
});
