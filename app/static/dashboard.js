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

        renderList(
            "alerts-list",
            payload.alerts.map((alert) => {
                const details = alert.details.length ? ` ${alert.details.join(" ")}` : "";
                return `${alert.message}${details}`;
            }),
            "Nenhum alerta identificado."
        );
        renderList("recommendations-list", payload.recommendations, "Nenhuma recomendação disponível.");

        const breachesList = document.getElementById("breaches-list");
        breachesList.replaceChildren();
        if (payload.breaches.length === 0) {
            const emptyState = document.createElement("p");
            emptyState.className = "breach-meta";
            emptyState.textContent = "Nenhuma brecha conhecida foi associada a este e-mail.";
            breachesList.appendChild(emptyState);
        } else {
            payload.breaches.forEach((breach) => {
                const item = document.createElement("article");
                item.className = "breach-item";

                const name = document.createElement("strong");
                name.className = "breach-name";
                name.textContent = breach.name;

                const metadata = document.createElement("p");
                metadata.className = "breach-meta";
                const date = breach.date || "Data não informada";
                const dataClasses = breach.data_classes.length
                    ? breach.data_classes.join(", ")
                    : "Tipos de dados não informados";
                const source = breach.source || "Fonte não informada";
                metadata.textContent = `${date} | Dados: ${dataClasses} | Fonte: ${source}`;

                item.append(name, metadata);
                breachesList.appendChild(item);
            });
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
