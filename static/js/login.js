"use strict";

function ajax(params) {
    return new Promise((resolve, reject) => {
        const req = new XMLHttpRequest();
        req.addEventListener("load", (evt) => {
            if(evt.target.status != 200) {
                reject("HTTP error " + evt.target.status);
            } else {
                if("json" in params && params.json)
                    resolve(JSON.parse(evt.target.responseText));
                else
                    resolve(evt.target.responseText);
            }
        });

        const method = "method" in params ? params.method : "GET";
        if(params.url == undefined)
            throw new Error("Params has no url");
        req.open(method, params.url);
        req.send();
    });
}

function onOk() {
    const login = document.getElementById("login-text").value;
    const password = document.getElementById("password-text").value;

    ajax({
        url: "/api/v1/login",
        method: "POST",
        json: true
    }).then((res) => {
        console.log(res);
    }).catch((err) => {
        console.error(err);
    });
}

function onLoad() {
    document.getElementById("ok-button").addEventListener("click", onOk);
}

window.addEventListener("load", onLoad);

