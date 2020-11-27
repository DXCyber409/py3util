
; function print_r(obj) {
    console.log("----------------");
    var description = "obj " + obj + ", typeof " + typeof obj + "\n";
    for (var i in obj) {
        var property = obj[i];
        description += i + " = " + property + "\n";
    }
    console.log(description);
    console.log("----------------");
}

; function logi(text) {
    console.log('[i] ' + new Date() + ' ' + text);
}

; function loge(text) {
    console.log('[e] ' + new Date() + ' ' + text);
}

; function logd(text) {
    console.log('[d] ' + new Date() + ' ' + text);
}

; function log(text) {
    logi(text);
}

; logi('script/common.js load success.');
