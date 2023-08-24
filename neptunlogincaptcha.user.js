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

const trueCaptchaUserId = "{{toBeReplaced}}";
const trueCaptchaApiKey = "{{toBeReplaced}}";

const $ = window.jQuery;
(function() {
    'use strict';

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