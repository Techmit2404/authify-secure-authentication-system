// Session start time
if (!sessionStorage.getItem("startTime")) {
  sessionStorage.setItem("startTime", Date.now());
}
if (!sessionStorage.getItem("darkMode")) {
  sessionStorage.setItem("darkMode", "true");
}

/* ========== AUTH FUNCTIONS ========== */

async function register(event) {
  event.preventDefault();

  const email = document.getElementById("regEmail").value;
  const password = document.getElementById("regPassword").value;

  const res = await fetch("http://localhost:3000/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error);
    return;
  }

  alert("Registration successful. Please login.");
  showLogin();
}


async function login(event) {
  event.preventDefault();

  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const res = await fetch("http://localhost:3000/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error);
    return;
  }

  // Store tokens
  sessionStorage.setItem("accessToken", data.accessToken);
  sessionStorage.setItem("refreshToken", data.refreshToken);
  sessionStorage.setItem("loginTime", Date.now());

  // Store refresh token expiry (7 days)
  const refreshExpiry = Date.now() + (7 * 24 * 60 * 60 * 1000);
  sessionStorage.setItem("refreshExpiry", refreshExpiry);

  // Decode role from access token
  const payload = JSON.parse(atob(data.accessToken.split(".")[1]));
  sessionStorage.setItem("role", payload.role);

  // Redirect
  if (payload.role === "admin") {
    window.location.href = "admin.html";
  } else {
    window.location.href = "user.html";
  }
}

async function refreshAccessToken() {
  const refreshToken = sessionStorage.getItem("refreshToken");

  if (!refreshToken) {
    logout();
    return null;
  }

  const res = await fetch("http://localhost:3000/refresh-token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken })
  });

  if (!res.ok) {
    logout();
    return null;
  }

  const data = await res.json();
  sessionStorage.setItem("accessToken", data.accessToken);

  return data.accessToken;
}

async function secureFetch(url, options = {}) {
  let token = sessionStorage.getItem("accessToken");

  options.headers = {
    ...options.headers,
    Authorization: "Bearer " + token
  };

  let res = await fetch(url, options);

  if (res.status === 401 || res.status === 403) {
    token = await refreshAccessToken();

    if (!token) return null;

    options.headers.Authorization = "Bearer " + token;
    res = await fetch(url, options);
  }

  return res;
}

/* ========== PAGE PROTECTION ========== */

function protectPage(requiredRole) {
  const token = sessionStorage.getItem("accessToken");
  const role = sessionStorage.getItem("role");

  if (!token) {
    window.location.href = "auth.html";
    return;
  }

  if (requiredRole && role !== requiredRole) {
    window.location.href = "auth.html";
  }
}

async function loadProfile() {
  const res = await secureFetch("http://localhost:3000/profile");

  if (!res) return;

  const data = await res.json();
  console.log("Profile data:", data);
}

//Admin Logs
async function loadLogs() {
  const res = await secureFetch("http://localhost:3000/admin/logs?limit=50");
  if (!res) return;

  const logs = await res.json();
  const table = document.querySelector("#logsTable tbody");
  table.innerHTML = "";

  logs.forEach(log => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${log.user_email}</td>
      <td>${log.action}</td>
      <td>${log.status}</td>
      <td>${log.role}</td>
      <td>${new Date(log.created_at).toLocaleString()}</td>
    `;
    table.appendChild(row);
  });
}

async function loadUsers() {
  const res = await secureFetch("http://localhost:3000/admin/users");
  if (!res) return;

  const users = await res.json();
  const table = document.querySelector("#usersTable tbody");
  table.innerHTML = "";

  users.forEach(user => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${user.email}</td>
      <td>${user.role}</td>
    `;
    table.appendChild(row);
  });
}

//Forgot Password
function showForgot() {
  document.getElementById("authBox").style.display = "none";
  document.getElementById("forgotView").style.display = "flex";
}

function showLogin() {
  document.getElementById("forgotView").style.display = "none";
  document.getElementById("authBox").style.display = "flex";
}

async function forgotPassword(event) {
  event.preventDefault();

  const email = document.getElementById("forgotEmail").value;

  const res = await fetch("http://localhost:3000/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error || "Failed to send reset token");
    return;
  }

  alert("Reset token sent. Check your email / console.");
  console.log("Reset Token:", data.resetToken); // for testing
}


async function resetPassword(event) {
  event.preventDefault();

  const token = document.getElementById("resetToken").value;
  const newPassword = document.getElementById("newPassword").value;

  const res = await fetch("http://localhost:3000/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, newPassword })
  });

  const data = await res.json();

  if (!res.ok) {
    alert(data.error || "Password reset failed");
    return;
  }

  alert("Password reset successful. You can now login.");
  window.location.href = "auth.html";
}

/* ========== UI FUNCTIONS ========== */

applyTheme();
startSessionTimer();
updateWeatherCard();

function toggleDarkMode() {
  const current = sessionStorage.getItem("darkMode") === "true";
  sessionStorage.setItem("darkMode", !current);
  applyTheme();
  updateWeatherCard();
  updateSettings();
}

function applyTheme() {
  const dark = sessionStorage.getItem("darkMode") === "true";

  if (dark) {
    document.body.classList.add("dark");
  } else {
    document.body.classList.remove("dark");
  }
}

function updateWeatherCard() {
  const dark = sessionStorage.getItem("darkMode") === "true";

  const title = document.getElementById("weatherTitle");
  const img = document.getElementById("weatherImage");
  const text = document.getElementById("weatherText");

  if (!title || !img || !text) return;

  if (dark) {
    title.textContent = "Good Night 🌙";
    img.src = "images/night.png";
    text.textContent =
      "Night brings calm, reflection, and focus under the quiet sky. The night arrives as a quiet exhale, wrapping the world in a heavy, velvet silence that softens the sharp edges of the day. As the sun’s warmth retreats, a cool stillness settles over the earth, lit only by the silver glow of the moon and the distant, rhythmic pulse of the stars.The night is not merely the absence of sun, but a gentle space to set down your burdens and dream the world anew.";
  } else {
    title.textContent = "Good Morning ☀️";
    img.src = "images/morning.png";
    text.textContent =
      "A fresh morning brings clarity, energy, and new opportunities.The world wakes in a soft glow of pink and gold, where the crisp air and dew-tipped grass offer a moment of pure, unwritten stillness before the day begins.The morning is not just a change in light, but a fresh invitation to see the world—and yourself—with brand new eyes.";
  }
}

function toggleSettings() {
  const popup = document.getElementById("settingsPopup");
  if (!popup) return;

  popup.style.display = popup.style.display === "block" ? "none" : "block";
  updateSettings();
}

function updateSettings() {
  const dark = sessionStorage.getItem("darkMode") === "true";
  const status = document.getElementById("darkStatus");
  if (status) status.textContent = dark ? "On" : "Off";
}

function startSessionTimer() {
  const timerEl = document.getElementById("sessionTimer");
  if (!timerEl) return;

  setInterval(() => {
    const expiry = parseInt(sessionStorage.getItem("refreshExpiry"));
    if (!expiry) return;

    const remaining = expiry - Date.now();

    if (remaining <= 0) {
      logout();
      return;
    }

    const days = Math.floor(remaining / (24 * 60 * 60 * 1000));
    const hours = Math.floor((remaining / (60 * 60 * 1000)) % 24);
    const minutes = Math.floor((remaining / (60 * 1000)) % 60);

    timerEl.textContent = `${days}d ${hours}h ${minutes}m`;
  }, 1000);
}

async function logout() {
  const token = sessionStorage.getItem("accessToken");

  if (token) {
    await fetch("http://localhost:3000/logout", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + token
      }
    });
  }

  sessionStorage.clear();
  window.location.href = "auth.html";
}


/* Auth Animation */

function showRegister() {
  const box = document.getElementById("authBox");
  if (box) box.classList.add("show-register");
}

function showLogin() {
  const box = document.getElementById("authBox");
  if (box) box.classList.remove("show-register");
}



