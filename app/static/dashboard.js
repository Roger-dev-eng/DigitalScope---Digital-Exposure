const form = document.getElementById("exposure-form");
const analyzeButton = document.getElementById("analyze-button");
const formStatus = document.getElementById("form-status");
const results = document.querySelectorAll(".results");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const email = new FormData(form).get("email");
    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analisando...";
    formStatus.className = "form-status";
    formStatus.textContent = "Consultando evidências...";

    try {
        const response = await fetch(`/api/exposure?email=${encodeURIComponent(email)}`);

        if (!response.ok) {
            const errorPayload = await response.json().catch(() => ({}));
            throw new Error(errorPayload.detail || "Não foi possível concluir a consulta.");
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

                const source = document.createElement("span");
                source.className = "breach-source";
                source.textContent = `Fonte: ${breach.source || "XposedOrNot"}`;

                metadata.append(date, document.createTextNode("|"), dataTooltip, document.createTextNode("|"), source);
                item.append(name, metadata);
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
        formStatus.textContent = "Consulta concluída.";
    } catch (error) {
        formStatus.className = "form-status error";
        formStatus.textContent = error.message;
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.textContent = "Analisar";
    }
});
