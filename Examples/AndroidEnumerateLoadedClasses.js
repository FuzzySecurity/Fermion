//-----------------------------//
// Android Enum Loaded Classes //
//-----------------------------//

Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            send("Class --> " + className);
        },
        onComplete: function() {}
    });
});