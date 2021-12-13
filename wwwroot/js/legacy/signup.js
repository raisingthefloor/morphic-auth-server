import { formValidation } from "./main.js";
import { register } from "./api.js";

$(function () {
  const form = document.getElementById("signupForm");
  const email = document.getElementById("email");
  const password = document.getElementById("password");
  const passwordConfirm = document.getElementById("passwordConfirm");

  // Ensure the passwordConfirm matches the password.
  $(password).on("input", function () {
    passwordConfirm.setAttribute("pattern", password.value);
  });

  formValidation(form, () => register(email.value, password.value, null, null));

});

