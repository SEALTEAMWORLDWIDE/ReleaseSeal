(() => {
  "use strict";

  const dialog = document.getElementById("screenshot-lightbox");
  if (!(dialog instanceof HTMLDialogElement)) {
    return;
  }

  const image = dialog.querySelector("img");
  const caption = dialog.querySelector("p");
  const closeButton = dialog.querySelector(".screenshot-lightbox-close");
  let opener = null;

  document.querySelectorAll(".screenshot-trigger").forEach((trigger) => {
    trigger.addEventListener("click", (event) => {
      event.preventDefault();
      const thumbnail = trigger.querySelector("img");
      if (!(thumbnail instanceof HTMLImageElement)) {
        return;
      }

      opener = trigger;
      image.src = trigger.href;
      image.alt = thumbnail.alt;
      caption.textContent = trigger.dataset.caption || "";
      dialog.showModal();
      closeButton.focus();
    });
  });

  closeButton.addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
  dialog.addEventListener("close", () => {
    image.removeAttribute("src");
    if (opener instanceof HTMLElement) {
      opener.focus();
    }
  });
})();
