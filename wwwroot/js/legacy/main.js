import { getToken, logout, useErrorHandler } from "./api.js";
import { config } from "./config.js";

/**
 * Add validation to a form.
 * @param {HTMLFormElement} form The form.
 * @param {function} onSubmit callback when the valid form is submitted.
 */
export function formValidation(form, onSubmit) {
  $("input", form).on("input", function (e) {
    e.target.hasChanged = e.target.value !== "";
  });

  // Validate on blur
  $("input", form).on("blur", function (e) {
    if (e.target.hasChanged) {
      $(e.target).parent()[0].classList.add("was-validated");
    }
  });

  // Validate the form on submit
  $(form).on("submit", function (e) {
    e.preventDefault();
    e.stopPropagation();
    const valid = form.checkValidity();
    form.classList.add("was-validated");

    if (valid) {
      const promise = onSubmit(e);

      if (promise && promise.then) {
        // Show the spinner on the submit button, hide it when the request is complete.
        form.classList.add("submitting");
        promise.catch(() => form.classList.remove("submitting"));
      }
    } else {
      autoFocus(form, true);
    }
  });

  // Password reveal button
  $(".input-password ~ .toggle-password", form).on("click", function (e) {
    e.preventDefault();
    e.stopPropagation();
    const input = document.getElementById(this.getAttribute("input-id"));
    const type = input.getAttribute("type");
    input.setAttribute("type", type === "password" ? "text" : "password");
    if (e.pointerType === "mouse") {
      input.focus();
    }
  });

  // Spinner on submit buttons
  const spinner = document.createElement("span");
  spinner.classList.add("spinner-border", "spinner-border-sm");
  $("button[type='submit']").append(spinner);

  autoFocus(form);
}

// Handle errors from the API server
$(function () {
  const alert = document.getElementById("formError");

  alert && useErrorHandler((errorMessage) => {
    alert.innerText = errorMessage;
  });
});

function autoFocus(form, invalid) {
  const input = invalid
    ? document.querySelector(`#${form.id} input:not(:disabled):invalid`)
    : document.querySelector(`#${form.id} input:not(:disabled)`);

  if (input) {
    input.focus();
  }
}


$(function () {
  $("template").each((i, elem) => makeComponent(elem));
  document.body.classList.add("loaded");
});

/**
 * Creates a component from a template
 * @param {HTMLTemplateElement} template The template element
 */
export function makeComponent(template) {
  const name = template.id.replace(/-component$/, "");

  customElements.define(name, class extends HTMLElement {
    constructor() {
      super();

      const newNode = document.createElement("div");

      // ${name} ${name?fallback} ${name?ifTrue:ifFalse}
      const interpolate = /\$\{(?<name>[^:}?]+)(:(?<fallback>[^}?]+))?(\?(?<ifTrue>[^:}]*):(?<ifFalse>[^}]*))?\}/g;

      // Replace the expanders in the template, with attribute values from the instance tag.
      newNode.innerHTML = template.innerHTML.replace(interpolate, (...args) => {
        const groups = args[args.length - 1];

        let value = this.getAttribute(groups.name);

        if (value === null) {
          value = groups.fallback === undefined ? null : groups.fallback;
        }

        if (groups.ifTrue !== undefined) {
          value = value == null ? groups.ifTrue : groups.ifFalse;
        }

        return value;
      });

      // Copy the attributes of the template onto the component instance
      Object.values(template.attributes).forEach(attr => {
        if (attr.nodeName !== "id" && newNode.getAttribute(attr.nodeName) === null) {
          newNode.setAttribute(attr.nodeName, attr.nodeValue);
        }
      });

      this.replaceWith(newNode);
    }
  });
}

// Load the reCAPTCHA script
$(function () {
  if (config.recaptchaSiteKey) {
    const script = document.createElement("script");
    script.src = `https://www.google.com/recaptcha/api.js?render=${config.recaptchaSiteKey}`;
    document.head.appendChild(script);
  }
});

export function showRecaptcha(show = true) {
  document.body.classList.toggle("show-recaptcha", !!show);
}

export function getRecaptchaToken(action) {
  /* global grecaptcha */
  return new Promise((resolve, reject) => {
    grecaptcha.ready(function () {
      try {
        grecaptcha.execute(config.recaptchaSiteKey, {action}).then(resolve, reject);
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error(e);
        reject(e);
      }
    });
  });
}

// Set a body class to show the authentication state.
$(function () {
  const loggedIn = !!getToken().token;

  document.body.classList.toggle("logged-in", loggedIn);
  document.body.classList.toggle("logged-out", !loggedIn);
});

// Log-out button
$(function () {
  $("#LogoutButton").on("click", function () {
    logout().then(() => {
      location.href = config.pages.login;
    });
  });
});
