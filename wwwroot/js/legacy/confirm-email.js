// eslint-disable-next-line no-unused-vars
import { formValidation } from "./main.js";
import { confirmEmail } from "./api.js";

/**
 * Set the confirmation response message.
 * @param {"confirmed", "confirmed-already", "bad-token", "error"} result
 */
function setResult(result) {
  const elem = document.getElementById("EmailConfirmationResponse");
  elem.classList.add(`is-${result}`);
}

$(async function () {

  const [userId, token] = (location.hash || "").replace(/^#\/?/, "").split("/", 2);
  if (userId && token) {
    try {
      await confirmEmail(userId, token);
      setResult("confirmed");
    } catch (err) {
      if (err?.response?.data?.error === "invalid_token") {
        setResult("bad-token");
        err.handled = true;
      } else {
        setResult("error");
      }
    }
  } else {
    setResult("bad-token");
  }

});

