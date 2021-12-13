import { formValidation } from "./main.js";
import { changePassword, getToken } from "./api.js";
import { config } from "./config.js";

if (!getToken().token) {
  // Need to be logged in to change the password.
  sessionStorage.setItem("errorMessage", "You need to sign in before changing your password");
  location.href = config.pages.login;
}

$(function () {

  const form = document.getElementById("passwordForm");
  const currentPassword = document.getElementById("currentPassword");
  const password = document.getElementById("password");
  const passwordConfirm = document.getElementById("passwordConfirm");

  formValidation(form, () => {
    changePassword(currentPassword.value, password.value).then(() => {
      location.href = new URL("#/password-changed", config.appBaseUrl);
    });
  });

  // Ensure the passwordConfirm matches the password.
  $(password).on("input", function () {
    passwordConfirm.setAttribute("pattern", password.value);
  });

});
