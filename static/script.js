// make enter click to send event
document.getElementById("url").addEventListener("keyup", function(event) {
    if (event.key === "Enter") {
        document.getElementById("check").click();
    }
});

document.getElementById("check").onclick = async () => {
    const url = document.getElementById("url").value.trim();
    if (!url) { alert("Enter URL"); return; }
    const legit = document.getElementById("legit");
    const probability = document.getElementById("probability");
    const message = document.getElementById("message");
    legit.style.display = "none";
    probability.style.display = "none";
    message.style.display = "block";
    message.textContent = "Verifying...";
    try {
        const resp = await fetch("http://0.0.0.0:8000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });
        const data = await resp.json();
        if (!resp.ok) {
            message.textContent = "Error: " + (data.detail || JSON.stringify(data));
            return;
        }
        const proba = data.phishing_probability;
        const pred = data.prediction;
        message.textContent = "";
        message.style.display = "none";
        legit.style.display = "block";
        probability.style.display = "block";
        legit.textContent = pred === 1 ? "PHISHING" : "LEGIT";
        legit.style.color = pred === 1 ? "red" : "green";
        probability.textContent = `Phishing probability: ${(proba * 100).toFixed(2)}%`;
    } catch (err) {
        message.textContent = "Connection error: " + err;
    }
}