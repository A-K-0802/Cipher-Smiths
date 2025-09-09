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
