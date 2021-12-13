import { formValidation } from "./main.js";
import { login } from "./api.js";

$(function () {
  const form = document.getElementById("loginForm");
  const email = document.getElementById("email");
  const password = document.getElementById("password");
  const successMessage = document.getElementById("successMessage");
  const formError = document.getElementById("formError");

  formValidation(form, () => login(email.value, password.value, null, null));

  const message = sessionStorage.getItem("successMessage");
  if (message) {
    sessionStorage.removeItem("successMessage");
    successMessage.innerText = message;
  }

  const errorMessage = sessionStorage.getItem("errorMessage");
  if (errorMessage) {
    sessionStorage.removeItem("errorMessage");
    formError.innerText = errorMessage;
  }

});
