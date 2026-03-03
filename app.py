from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Phishing URL Detector</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 680px;
      box-shadow: 0 25px 50px rgba(0,0,0,0.4);
    }
    h1 { color: #1a1a2e; font-size: 26px; margin-bottom: 6px; }
    .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
    .input-row {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
    }
    input {
      flex: 1;
      padding: 14px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 10px;
      font-size: 15px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #0f3460; }
    button {
      padding: 14px 24px;
      background: #0f3460;
      color: white;
      border: none;
      border-radius: 10px;
      font-size: 15px;
      cursor: pointer;
      transition: background 0.2s;
      white-space: nowrap;
    }
    button:hover { background: #1a5276; }
    button:disabled { background: #999; cursor: not-allowed; }
    #result { display: none; }
    .result-card {
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 16px;
    }
    .result-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    .prediction-label { font-size: 22px; font-weight: 700; }
    .risk-badge {
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      color: white;
    }
    .score-section { margin-bottom: 16px; }
    .score-label {
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 14px;
      font-weight: 600;
    }
    .score-bar {
      background: #eee;
      border-radius: 10px;
      height: 18px;
      overflow: hidden;
    }
    .score-fill {
      height: 100%;
      border-radius: 10px;
      transition: width 0.8s ease;
    }
    .url-display {
      background: #f8f8f8;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 13px;
      color: #333;
      word-break: break-all;
      margin-bottom: 16px;
    }
    .flags-section h4 {
      font-size: 14px;
      margin-bottom: 8px;
      color: #c0392b;
    }
    .flag-item {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: #555;
      margin-bottom: 4px;
    }
    .flag-item::before { content: "⚠️"; }
    .no-flags { font-size: 13px; color: #27ae60; }
    .loading { text-align: center; padding: 20px; color: #666; display: none; }
    .examples { margin-top: 20px; }
    .examples p { font-size: 13px; color: #888; margin-bottom: 8px; }
    .example-btn {
      background: #f0f4f8;
      color: #333;
      padding: 6px 12px;
      font-size: 12px;
      border-radius: 6px;
      margin: 3px;
      cursor: pointer;
      border: 1px solid #ddd;
    }
    .example-btn:hover { background: #dce8f5; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔐 Phishing URL Detector</h1>
    <p class="subtitle">Powered by LightGBM + CatBoost Ensemble with Anti-Phishing Score</p>

    <div class="input-row">
      <input type="text" id="urlInput" placeholder="Enter URL to check (e.g. https://example.com)" />
      <button onclick="checkURL()" id="checkBtn">Check URL</button>
    </div>

    <div class="loading" id="loading">🔍 Analyzing URL...</div>

    <div id="result">
      <div class="result-card" id="resultCard">
        <div class="result-header">
          <div class="prediction-label" id="predLabel"></div>
          <div class="risk-badge" id="riskBadge"></div>
        </div>
        <div class="url-display" id="urlDisplay"></div>
        <div class="score-section">
          <div class="score-label">
            <span>Anti-Phishing Score</span>
            <span id="scoreText"></span>
          </div>
          <div class="score-bar">
            <div class="score-fill" id="scoreBar"></div>
          </div>
        </div>
        <div class="flags-section" id="flagsSection"></div>
      </div>
    </div>

    <div class="examples">
      <p>Try examples:</p>
      <button class="example-btn" onclick="setURL('https://google.com')">google.com</button>
      <button class="example-btn" onclick="setURL('https://paypal-secure-login.tk/verify')">paypal-secure-login.tk</button>
      <button class="example-btn" onclick="setURL('https://github.com')">github.com</button>
      <button class="example-btn" onclick="setURL('http://192.168.1.1/bank/login')">IP-based URL</button>
    </div>
  </div>

  <script>
    function setURL(url) {
      document.getElementById('urlInput').value = url;
      checkURL();
    }

    async function checkURL() {
      const url = document.getElementById('urlInput').value.trim();
      if (!url) { alert('Please enter a URL'); return; }

      document.getElementById('checkBtn').disabled = true;
      document.getElementById('loading').style.display = 'block';
      document.getElementById('result').style.display = 'none';

      try {
        const res = await fetch('/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url })
        });
        const data = await res.json();

        if (data.error) { alert(data.error); return; }

        // Color mapping
        const colors = {
          green: { bg: '#eafaf1', border: '#27ae60', badge: '#27ae60' },
          orange: { bg: '#fef9e7', border: '#f39c12', badge: '#f39c12' },
          red: { bg: '#fdf2f2', border: '#e74c3c', badge: '#e74c3c' },
          darkred: { bg: '#f9ebea', border: '#c0392b', badge: '#c0392b' }
        };
        const c = colors[data.color] || colors.green;

        document.getElementById('resultCard').style.cssText =
          `background:${c.bg}; border: 2px solid ${c.border}`;
        document.getElementById('predLabel').textContent =
          (data.color === 'green' ? '✅ ' : '🚨 ') + data.prediction;
        document.getElementById('predLabel').style.color = c.border;

        const badge = document.getElementById('riskBadge');
        badge.textContent = data.risk_level;
        badge.style.background = c.badge;

        document.getElementById('urlDisplay').textContent = data.url;
        // Calculate Risk Score
        const riskScore = ((1 - data.anti_phishing_score) * 100).toFixed(2);
        const antiScorePercent = (data.anti_phishing_score * 100).toFixed(2);

        document.getElementById('scoreText').textContent =
          `Risk Score: ${riskScore}% | Anti-Phishing Score: ${antiScorePercent}% | Confidence: ${data.confidence}%`;
          

        const bar = document.getElementById('scoreBar');
        bar.style.width = riskScore + '%';
        bar.style.background = c.border;

        const flagsDiv = document.getElementById('flagsSection');
        if (data.red_flags && data.red_flags.length > 0) {
          flagsDiv.innerHTML = '<h4>Red Flags Detected:</h4>' +
            data.red_flags.map(f => `<div class="flag-item">${f}</div>`).join('');
        } else {
          flagsDiv.innerHTML = '<p class="no-flags">✅ No red flags detected</p>';
        }

        document.getElementById('result').style.display = 'block';
      } catch (err) {
        alert('Error: ' + err.message);
      } finally {
        document.getElementById('checkBtn').disabled = false;
        document.getElementById('loading').style.display = 'none';
      }
    }

    document.getElementById('urlInput').addEventListener('keypress', e => {
      if (e.key === 'Enter') checkURL();
    });
  </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/predict', methods=['POST'])
def predict():
    from src.predict import predict_url
    data = request.json
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    try:
        result = predict_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    from src.predict import load_models
    load_models()
    app.run(debug=True, port=5000)