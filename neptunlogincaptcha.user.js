// ==UserScript==
// @name         Neptun Captcha Fill
// @namespace    https://atipls.com
// @version      0.1
// @description  Utálom a captcha-t :( !!!
// @author       atipls
// @include      https://*neptun*/*hallgato*/*Login*
// @icon         https://www.google.com/s2/favicons?sz=64&domain=pte.hu
// @grant        GM.xmlHttpRequest
// @grant        GM.getValue
// @grant        GM.setValue
// @grant        GM.info
// @require      https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js
// ==/UserScript==

const $ = window.jQuery;
(async function() {
    'use strict';

    const trueCaptchaUserId = await GM.getValue("trueCaptchaUserId", "");
    const trueCaptchaApiKey = await GM.getValue("trueCaptchaApiKey", "");

    if (trueCaptchaUserId === "" || trueCaptchaApiKey === "") {
        const userId = prompt("TrueCaptcha User ID");
        const apiKey = prompt("TrueCaptcha API Key");
        await GM.setValue("trueCaptchaUserId", userId);
        await GM.setValue("trueCaptchaApiKey", apiKey);

        location.reload();
    }

    $("#loginCaptcha img").on("load", function() {
        const canvas = document.createElement("canvas");
        canvas.width = this.naturalWidth;
        canvas.height = this.naturalHeight;

        const context = canvas.getContext("2d");

        context.drawImage(this, 0, 0);

        const base64ImageData = canvas.toDataURL("image/png");
        const captchaApiImageData = base64ImageData.replace(/^data:image\/(png|jpg|jpeg|gif);base64,/, "");
        console.log(captchaApiImageData);

        fetch("https://api.apitruecaptcha.org/one/gettext", {
            method: "post",
            body: JSON.stringify({
                userid: trueCaptchaUserId,
                apikey: trueCaptchaApiKey,
                data: captchaApiImageData,
                numeric: true,
                len_str: 6,
            }),
        }).then(response => response.json()).then(data => {
            $("#cap").val(data.result);
        });
    });
})();