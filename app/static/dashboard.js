const form = document.getElementById("exposure-form");
const analyzeButton = document.getElementById("analyze-button");
const formStatus = document.getElementById("form-status");
const results = document.querySelectorAll(".results");
const emailInput = form.elements.email;

emailInput.addEventListener("invalid", () => {
    formStatus.className = "form-status error";
    formStatus.textContent = emailInput.validity.valueMissing
        ? "Digite seu e-mail para continuar."
        : "Digite um endereço de e-mail válido (ex.: nome@exemplo.com).";
});

emailInput.addEventListener("input", () => {
    if (emailInput.validity.valid) {
        formStatus.className = "form-status";
        formStatus.textContent = "";
    }
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!emailInput.validity.valid) {
        emailInput.reportValidity();
        return;
    }

    const email = new FormData(form).get("email");
    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analisando...";
    formStatus.className = "form-status";
    formStatus.textContent = "Consultando evidências...";

    try {
        const response = await fetch(`/api/exposure?email=${encodeURIComponent(email)}`);

        if (!response.ok) {
            const errorPayload = await response.json().catch(() => ({}));
            if (response.status === 422) {
                throw new Error("O e-mail informado é inválido. Digite um endereço válido, como nome@exemplo.com.");
            }
            if (response.status === 429) {
                const providerLimited = typeof errorPayload.detail === "string"
                    && errorPayload.detail.toLowerCase().includes("provider");
                throw new Error(providerLimited
                    ? "O XposedOrNot limitou as consultas. Aguarde um pouco e tente novamente."
                    : "O limite de consultas do aplicativo foi atingido. Aguarde um pouco e tente novamente.");
            }
            if (response.status === 502) {
                throw new Error("O servidor do XposedOrNot está indisponível no momento. Tente novamente mais tarde.");
            }

            const detail = errorPayload.detail;
            const message = typeof detail === "string"
                ? detail
                : "Não foi possível concluir a consulta. Tente novamente.";
            throw new Error(message);
        }

        const payload = await response.json();
        document.getElementById("breach-count").textContent = payload.summary.breach_count;
        const severityLabels = { low: "Baixa", medium: "Média", high: "Alta" };
        document.getElementById("severity").textContent = severityLabels[payload.summary.severity] || payload.summary.severity;
        document.getElementById("exposed-count").textContent = payload.summary.exposed_data_types.length;
        document.getElementById("alert-count").textContent = payload.alerts.length;
        document.getElementById("account-count").textContent = payload.breaches.length;


        const renderList = (elementId, items, emptyMessage) => {
            const list = document.getElementById(elementId);
            list.replaceChildren();
            (items.length ? items : [emptyMessage]).forEach((item) => {
                const listItem = document.createElement("li");
                listItem.textContent = item;
                list.appendChild(listItem);
            });
        };

        const alertItems = [];
        payload.alerts.forEach((alert) => {
            alertItems.push(alert.message);
            alert.details.forEach((detail) => alertItems.push(detail));
        });
        renderList("alerts-list", alertItems, "Nenhum alerta identificado.");
        renderList("recommendations-list", payload.recommendations, "Nenhuma recomendação disponível.");

        const breachesList = document.getElementById("breaches-list");
        const pagination = document.getElementById("breach-pagination");
        const previousPage = document.getElementById("previous-page");
        const nextPage = document.getElementById("next-page");
        const paginationStatus = document.getElementById("pagination-status");
        const pageSize = 5;
        let currentPage = 1;

        const renderBreaches = () => {
            breachesList.replaceChildren();
            const totalPages = Math.max(1, Math.ceil(payload.breaches.length / pageSize));
            const start = (currentPage - 1) * pageSize;
            const visibleBreaches = payload.breaches.slice(start, start + pageSize);

            visibleBreaches.forEach((breach) => {
                const item = document.createElement("article");
                item.className = "breach-item";

                const name = document.createElement("strong");
                name.className = "breach-name";
                name.textContent = breach.name;

                const metadata = document.createElement("div");
                metadata.className = "breach-meta";

                const date = document.createElement("span");
                date.className = "breach-date";
                date.textContent = `Data: ${breach.date || "Data não informada"}`;

                const source = document.createElement("span");
                source.className = "breach-source";
                source.textContent = `Fonte: ${breach.source || "XposedOrNot"}`;

                metadata.append(date);
                if (breach.details_available) {
                    const dataTooltip = document.createElement("span");
                    dataTooltip.className = "data-tooltip";
                    const dataTrigger = document.createElement("button");
                    dataTrigger.className = "data-tooltip-trigger";
                    dataTrigger.type = "button";
                    dataTrigger.textContent = "Dados vazados";
                    const dataContent = document.createElement("span");
                    dataContent.className = "data-tooltip-content";
                    dataContent.textContent = breach.data_classes.length
                        ? breach.data_classes.join(", ")
                        : "Tipos de dados não informados";
                    dataTooltip.append(dataTrigger, dataContent);
                    metadata.append(document.createTextNode("|"), dataTooltip);
                }
                metadata.append(document.createTextNode("|"), source);
                item.append(name, metadata);
                if (!breach.details_available) {
                    const detailsError = document.createElement("p");
                    detailsError.className = "breach-meta";
                    detailsError.textContent = "Não foi possível carregar os detalhes deste incidente.";
                    item.appendChild(detailsError);
                }
                breachesList.appendChild(item);
            });

            paginationStatus.textContent = `Página ${currentPage} de ${totalPages}`;
            previousPage.disabled = currentPage === 1;
            nextPage.disabled = currentPage === totalPages;
            pagination.hidden = payload.breaches.length <= pageSize;
        };

        previousPage.onclick = () => {
            if (currentPage > 1) {
                currentPage -= 1;
                renderBreaches();
            }
        };
        nextPage.onclick = () => {
            if (currentPage < Math.ceil(payload.breaches.length / pageSize)) {
                currentPage += 1;
                renderBreaches();
            }
        };

        if (payload.breaches.length === 0) {
            const emptyState = document.createElement("p");
            emptyState.className = "breach-meta";
            emptyState.textContent = "Nenhuma brecha conhecida foi associada a este e-mail.";
            breachesList.appendChild(emptyState);
            pagination.hidden = true;
        } else {
            renderBreaches();
        }
        results.forEach((element) => element.classList.add("is-visible"));
        formStatus.className = "form-status";
        const detailsUnavailable = payload.breaches.some((breach) => !breach.details_available);
        formStatus.textContent = payload.breaches.length === 0
            ? "Nenhuma exposição conhecida foi encontrada nas fontes consultadas para este e-mail. Isso não garante que não existam exposições em outras fontes."
            : detailsUnavailable
                ? "A busca encontrou incidentes, mas não foi possível carregar os detalhes."
                : "Consulta concluída. Foram encontradas exposições associadas a este e-mail.";
    } catch (error) {
        formStatus.className = "form-status error";
        formStatus.textContent = error.message;
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analisar";
    }
});
