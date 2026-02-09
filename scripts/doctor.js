const required = ["TELEGRAM_TOKEN", "SESSION_SECRET", "ADMIN_IDS"];

const missing = required.filter((key) => !process.env[key]);
if (missing.length) {
  console.error(`Missing env vars: ${missing.join(", ")}`);
} else {
  console.log("Env vars: OK");
}

if (process.env.BASE_URL) {
  const url = `${process.env.BASE_URL.replace(/\/$/, "")}/api/v1/health/full`;
  try {
    const res = await fetch(url);
    const data = await res.json();
    if (data.status === "ok") {
      console.log("Health: OK");
    } else {
      console.warn("Health: WARNING", data);
    }
  } catch (err) {
    console.error("Health: FAILED", err.message);
  }
} else {
  console.warn("BASE_URL not set, skipping remote health check.");
}
