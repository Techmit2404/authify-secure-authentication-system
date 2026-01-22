const API = "http://localhost:3000";

async function login() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const res = await fetch(API + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();

  if (data.token) {
    localStorage.setItem("token", data.token);
    window.location.href = "dashboard.html";
  } else {
    document.getElementById("msg").innerHTML =
      `<div class="alert">⚠ SECURITY ALERT:${data.error}</div>`;
  }
}

async function register() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const res = await fetch(API + "/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();

  document.getElementById("msg").innerHTML =
    `<div class="${data.message ? "success" : "alert"}">
      ${data.message || data.error}
    </div>`;
}

async function loadDashboard() {
  const token = localStorage.getItem("token");

  const res = await fetch(API + "/profile", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();

  if (data.user?.role === "admin") {
    window.location.href = "admin.html";
    return;
  }

  startSessionTimer();
  document.getElementById("info").innerText =
    "SECURE SESSION INITIATED: " + data.user.email;
}

async function loadAdmin() {
  const token = localStorage.getItem("token");

  const res = await fetch(API + "/admin", {
    headers: { "Authorization": "Bearer " + token }
  });

  const data = await res.json();

  document.getElementById("adminInfo").innerText =
    data.message || data.error;
}

async function loadAdmin() {
  const token = localStorage.getItem("token");

  const res = await fetch(API + "/admin/users", {
    headers: { "Authorization": "Bearer " + token }
  });

  const users = await res.json();

  const table = document.getElementById("userTable");

  users.forEach(u => {
    const row = document.createElement("tr");
    row.innerHTML = `<td>${u.email}</td><td>${u.role}</td>`;
    table.appendChild(row);
  });

  document.getElementById("adminInfo").
  startSessionTimer();
  innerText =
    "ADMIN PANEL ACTIVE — ROLE-BASED CONTROL ENABLED";
}

function startSessionTimer() {
  let timeLeft = 60; // seconds for demo (you can set 3600)

  const warning = document.createElement("div");
  warning.className = "alert";
  document.body.appendChild(warning);

  const interval = setInterval(() => {
    warning.innerText = `URGENT: SESSION EXPIRING IN ${timeLeft}s — RE-AUTHENTICATE`;
    timeLeft--;

    if (timeLeft <= 0) {
      clearInterval(interval);
      logout();
    }
  }, 1000);
}


function logout() {
  localStorage.removeItem("token");
  window.location.href = "login.html";
}

if (location.pathname.includes("dashboard")) loadDashboard();
if (location.pathname.includes("admin")) loadAdmin();
