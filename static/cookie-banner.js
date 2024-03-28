document.addEventListener("DOMContentLoaded", () => {
  const cookieBanner = document.getElementById("cookie-banner");
  const acceptBtn = document.getElementById("accept-cookies");
  const declineBtn = document.getElementById("decline-cookies");

  const setCookie = () => {
    document.cookie = "cookie_consent=true";
    window.location.reload();
  };

  if (cookieBanner) {
    acceptBtn.addEventListener("click", () => setCookie());

    declineBtn.addEventListener("click", () => {
      cookieBanner.style.display = "none";
    });
  }
});
