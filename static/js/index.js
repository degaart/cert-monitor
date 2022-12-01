"use strict";

let elementMap = {};
//let fetchingHost = 0;

function onLoad() {
    elementMap = {};
    const tbody = document.getElementById("table-data");
    for(const host of hosts) {
        const tr = document.createElement("tr");
        const tdName = document.createElement("td");
        tdName.textContent = host;
        tr.appendChild(tdName);

        const tdNotBefore = document.createElement("td");
        tdNotBefore.textContent = "Loading...";
        tr.appendChild(tdNotBefore);
        elementMap[host] = {};
        elementMap[host]["not_before"] = tdNotBefore;

        const tdNotAfter = document.createElement("td");
        tdNotAfter.textContent = "Loading...";
        tr.appendChild(tdNotAfter);
        elementMap[host]["not_after"] = tdNotAfter;

        tbody.appendChild(tr);

        const req = new XMLHttpRequest();
        req.addEventListener("load", (evt) => {
            if(evt.target.status == 200) {
                const response = JSON.parse(evt.target.responseText);
                if(response.error) {
                    elementMap[host].not_before.textContent = response.error;
                    elementMap[host].not_after.textContent = response.error;
                } else {
                    elementMap[host].not_before.textContent = response.not_before;
                    elementMap[host].not_after.textContent = response.not_after;
                    if(response.is_invalid)
                        elementMap[host].not_before.classList.add("invalid");
                    if(response.is_expired)
                        elementMap[host].not_after.classList.add("invalid");
                }
            } else {
                console.err(evt.target.responseText);
            }
        });
        req.open("GET", "/api/v1/host/" + encodeURIComponent(host) + "?" + new Date().getTime());
        req.send();
    }
}

window.addEventListener("load", onLoad);
