document.addEventListener("DOMContentLoaded", function () {
    const serviceSelect = document.getElementById("service_name");
    const customService = document.getElementById("custom_service");
    const generatorForm = document.getElementById("generator-form");

    if (serviceSelect && customService && generatorForm) {
        generatorForm.addEventListener("submit", function (event) {
            const customName = customService.value.trim();

            if (customName) {
                if (customName.length > 120) {
                    event.preventDefault();
                    alert("Service name must be 120 characters or fewer.");
                    return;
                }

                let option = Array.from(serviceSelect.options).find(
                    item => item.value === customName
                );

                if (!option) {
                    option = document.createElement("option");
                    option.value = customName;
                    option.textContent = customName;
                    serviceSelect.appendChild(option);
                }

                serviceSelect.value = customName;
            }
        });
    }

    const copyButton = document.getElementById("copy-password");
    const passwordElement = document.getElementById("revealed-password");

    if (copyButton && passwordElement) {
        copyButton.addEventListener("click", async function () {
            try {
                await navigator.clipboard.writeText(
                    passwordElement.textContent
                );
                copyButton.textContent = "Copied";
            } catch {
                alert(
                    "Clipboard access is unavailable. Select the password and copy it manually."
                );
            }
        });
    }
});