import { formValidation, getRecaptchaToken, showRecaptcha } from "./main.js";
import { resetPassword } from "./api.js";
import { config } from "./config.js";

$(function () {

  showRecaptcha();

  const form = document.getElementById("loginForm");
  const email = document.getElementById("email");

  formValidation(form, () => {
    return getRecaptchaToken("requestpasswordreset").then(token => {
      return resetPassword(email.value, token).then(() => {
        sessionStorage.setItem("successMessage", "Instructions to recover your password have been emailed to you.");
        location.href = config.pages.login;
      });
    });
  });
});

