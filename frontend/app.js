console.log("AI Security Dashboard Loaded ✅");

// ----------------------
// DARK / LIGHT MODE (controlled only from Settings)
// ----------------------
const toggle = document.getElementById("darkModeToggle");

// Apply saved theme everywhere
if (localStorage.getItem("theme") === "dark") {
  document.body.classList.add("dark-mode");
} else {
  document.body.classList.remove("dark-mode");
}

// Only in Settings page toggle exists
if (toggle) {
  toggle.checked = localStorage.getItem("theme") === "dark";
  toggle.addEventListener("change", () => {
    if (toggle.checked) {
      document.body.classList.add("dark-mode");
      localStorage.setItem("theme", "dark");
    } else {
      document.body.classList.remove("dark-mode");
      localStorage.setItem("theme", "light");
    }
  });
}

// ----------------------
// OVERVIEW PAGE CHARTS
// ----------------------
if (document.getElementById("lineChart")) {
  new Chart(document.getElementById("lineChart"), {
    type: 'line',
    data: {
      labels: ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],
      datasets: [{
        label: "Threats",
        data: [12,19,8,15,22,9,14],
        borderColor: "#007bff",
        backgroundColor: "rgba(0,123,255,0.2)",
        tension: 0.3
      }]
    },
    options: { responsive:true, maintainAspectRatio:false }
  });
}

if (document.getElementById("doughnutChart")) {
  new Chart(document.getElementById("doughnutChart"), {
    type: 'doughnut',
    data: {
      labels: ["Malware","Phishing","DDoS","Exploits"],
      datasets: [{
        data: [25,35,20,20],
        backgroundColor:["#ff4d4d","#007bff","#ffcc00","#28a745"]
      }]
    },
    options: { responsive:true, maintainAspectRatio:false }
  });
}

// ----------------------
// ANALYSIS PAGE CHARTS
// ----------------------
if (document.getElementById("pieChart")) {
  new Chart(document.getElementById("pieChart"), {
    type: 'pie',
    data: {
      labels: ["Malware","Phishing","DDoS","Exploits"],
      datasets: [{
        data: [25,35,20,20],
        backgroundColor:["#ff4d4d","#007bff","#ffcc00","#28a745"]
      }]
    },
    options: { responsive:true, maintainAspectRatio:false }
  });
}

if (document.getElementById("barChart")) {
  new Chart(document.getElementById("barChart"), {
    type: 'bar',
    data: {
      labels: ["192.168.0.1","10.0.0.5","203.0.113.45"],
      datasets: [{
        label: "Attacks",
        data: [12,7,19],
        backgroundColor:"#ff6600"
      }]
    },
    options: { responsive:true, maintainAspectRatio:false }
  });
}

// ----------------------
// MONITORING PAGE MINI CHART
// ----------------------
if (document.getElementById("miniChart")) {
  new Chart(document.getElementById("miniChart"), {
    type:'line',
    data:{
      labels:["12:00","12:05","12:10","12:15"],
      datasets:[{
        data:[5,12,8,15],
        borderColor:"#0dcaf0",
        backgroundColor:"rgba(13,202,240,0.2)",
        fill:true,
        tension:0.3
      }]
    },
    options:{
      responsive:true,
      maintainAspectRatio:false,
      plugins:{ legend:{ display:false } }
    }
  });
}



const analyzeBtn = document.getElementById("analyzeBtn");
const fileInput = document.getElementById("fileInput");
const uploadStatus = document.getElementById("uploadStatus");

if (analyzeBtn) {
  analyzeBtn.addEventListener("click", async () => {
    const file = fileInput.files[0];
    if (!file) {
      uploadStatus.innerHTML = "<span style='color:red;'>Please select a CSV file first.</span>";
      return;
    }

    let formData = new FormData();
    formData.append("file", file);

    uploadStatus.innerHTML = "⏳ Uploading and analyzing...";

    try {
      const response = await fetch("http://127.0.0.1:8000/predict/", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      console.log("Backend response:", data);

      uploadStatus.innerHTML = `✅ Analysis Complete: 
        ${data.summary.attacks_detected} attacks found 
        out of ${data.summary.total_events} events.`;

      // Render results dynamically
      renderResultsTable(data.results);
      renderCharts(data.results);

    } catch (err) {
      console.error(err);
      uploadStatus.innerHTML = "<span style='color:red;'>Error connecting to backend.</span>";
    }
  });
}

function renderResultsTable(results) {
  const container = document.getElementById("resultsTable");
  if (!container) return;

  let tableHTML = `
    <table border="1" cellpadding="6">
      <thead>
        <tr>
          <th>Event ID</th>
          <th>Destination Port</th>
          <th>Service</th>
          <th>Protocol</th>
          <th>Prediction</th>
          <th>Confidence</th>
          <th>Risk Score</th>
        </tr>
      </thead>
      <tbody>
  `;

  results.slice(0, 50).forEach(r => {
    tableHTML += `
      <tr style="background:${r['Risk Score']==='HIGH' ? '#ffcccc':'#ccffcc'};">
        <td>${r["Event ID"]}</td>
        <td>${r["Destination Port"]}</td>
        <td>${r["Service"]}</td>
        <td>${r["Protocol"]}</td>
        <td>${r["Prediction"]}</td>
        <td>${r["Confidence"]}</td>
        <td>${r["Risk Score"]}</td>
      </tr>`;
  });

  tableHTML += "</tbody></table>";
  container.innerHTML = tableHTML;
}

function renderCharts(results) {
  // Count attack types
  const attackCount = results.filter(r => r.Prediction === "Attack").length;
  const normalCount = results.length - attackCount;

  // Pie Chart
  if (document.getElementById("pieChart")) {
    new Chart(document.getElementById("pieChart"), {
      type: 'pie',
      data: {
        labels: ["Normal", "Attack"],
        datasets: [{
          data: [normalCount, attackCount],
          backgroundColor: ["#28a745","#ff4d4d"]
        }]
      }
    });
  }

  // Bar Chart (top risky ports)
  let portCounts = {};
  results.forEach(r => {
    if (r.Prediction === "Attack") {
      portCounts[r["Destination Port"]] = (portCounts[r["Destination Port"]] || 0) + 1;
    }
  });

  const topPorts = Object.entries(portCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  if (document.getElementById("barChart")) {
    new Chart(document.getElementById("barChart"), {
      type: 'bar',
      data: {
        labels: topPorts.map(x => x[0]),
        datasets: [{
          label: "Attacks",
          data: topPorts.map(x => x[1]),
          backgroundColor:"#ff6600"
        }]
      }
    });
  }
}
